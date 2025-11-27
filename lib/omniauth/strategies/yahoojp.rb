# frozen_string_literal: true

require 'omniauth-oauth2'
require 'json/jwt'
require 'digest'
require 'base64'

module OmniAuth
  module Strategies
    class Yahoojp < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = 'openid profile email'
      DEFAULT_JWT_LEEWAY = 600
      USER_INFO_URL = 'https://userinfo.yahooapis.jp/yconnect/v2/attribute'
      JWKS_URL = 'https://auth.login.yahoo.co.jp/yconnect/v2/jwks'
      ID_TOKEN_ISSUER = 'https://auth.login.yahoo.co.jp/yconnect/v2'

      option :name, 'yahoojp'
      option :client_options, {
        site: 'https://auth.login.yahoo.co.jp',
        authorize_url: '/yconnect/v2/authorization',
        token_url: '/yconnect/v2/token'
      }
      option :authorize_options, [:scope, :state, :nonce, :prompt, :display, :max_age, :bail]
      option :pkce, true
      option :scope, DEFAULT_SCOPE
      option :jwt_leeway, DEFAULT_JWT_LEEWAY
      option :skip_jwt, false

      uid { raw_info['sub'] }

      info do
        prune!({
          name: raw_info['name'],
          nickname: raw_info['nickname'],
          first_name: raw_info['given_name'],
          first_name_kana: raw_info['given_name#ja-Kana-JP'],
          first_name_hani: raw_info['given_name#ja-Hani-JP'],
          last_name: raw_info['family_name'],
          last_name_kana: raw_info['family_name#ja-Kana-JP'],
          last_name_hani: raw_info['family_name#ja-Hani-JP'],
          gender: raw_info['gender'],
          zoneinfo: raw_info['zoneinfo'],
          locale: raw_info['locale'],
          birth_year: raw_info['birthdate']&.to_i,
          image: raw_info['picture'],
          email: raw_info['email'],
          email_verified: raw_info['email_verified'] == 'true',
          address: raw_info['address']&.transform_keys(&:to_sym)
        })
      end

      extra do
        hash = {}
        hash[:raw_info] = raw_info unless skip_info?
        hash[:id_token] = id_token_info[:raw] if id_token_info[:raw]
        hash[:id_info] = id_token_info[:decoded] if id_token_info[:decoded]
        prune!(hash)
      end

      credentials do
        hash = { token: access_token.token }
        hash[:expires] = access_token.expires?
        hash[:expires_at] = access_token.expires_at if access_token.expires?
        hash[:refresh_token] = access_token.refresh_token if access_token.refresh_token
        hash
      end

      def raw_info
        return @raw_info if defined?(@raw_info)

        if skip_info?
          decoded_id_token = decode_id_token(access_token.params['id_token'])
          @raw_info = { 'sub' => decoded_id_token[:sub] }
        else
          @raw_info = access_token.get(USER_INFO_URL, headers: { 'Authorization' => "Bearer #{access_token.token}" }).parsed
        end
        @raw_info
      end

      def callback_url
        options[:redirect_uri] || (full_host + callback_path)
      end

      def authorize_params # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity
        super.tap do |params|
          options[:authorize_options].each do |key|
            params[key] = request.params[key.to_s] unless empty?(request.params[key.to_s])
          end
          params[:scope] ||= DEFAULT_SCOPE
          params[:nonce] ||= SecureRandom.hex(24)
          params[:response_type] = 'code'
          session['omniauth.state'] = params[:state] unless empty?(params[:state])
          session['omniauth.nonce'] = params[:nonce] unless empty?(params[:nonce])
          session['omniauth.max_age'] = params[:max_age] unless empty?(params[:max_age])
        end
      end

      private

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          empty?(value)
        end
      end

      def empty?(value)
        value.nil? || (value.respond_to?(:empty?) && value.empty?)
      end

      def decode_id_token(id_token)
        JSON::JWT.decode(id_token, :skip_verification)
      end

      def id_token_info
        return @id_token_info if defined?(@id_token_info)

        @id_token_info = { raw: nil, decoded: nil }
        return @id_token_info unless access_token.params['id_token']

        @id_token_info[:raw] = access_token.params['id_token']
        return @id_token_info if skip_info?

        decoded_id_token = decode_id_token(access_token.params['id_token'])
        verify_id_token(decoded_id_token) unless options.skip_jwt
        @id_token_info[:decoded] = decoded_id_token
        @id_token_info
      end

      def verify_id_token(id_token)
        jwk = fetch_jwk(id_token.kid)
        verify_signature(id_token, jwk)
        verify_claims(id_token)
      rescue StandardError => e
        fail!(:id_token_verification_failed, e)
      end

      def fetch_jwk(kid)
        JSON::JWK::Set::Fetcher.fetch(JWKS_URL, kid: kid)
      rescue StandardError => e
        fail!(:jwk_fetch_failed, e)
      end

      def verify_signature(id_token, jwk)
        id_token.verify!(jwk)
      rescue StandardError => e
        fail!(:id_token_signature_invalid, e)
      end

      def verify_claims(id_token)
        verify_iss(id_token)
        verify_aud(id_token)
        verify_nonce(id_token)
        verify_at_hash(id_token)
        verify_c_hash(id_token)
        verify_exp(id_token)
        verify_iat(id_token)
        verify_auth_time(id_token)
      end

      def verify_iss(id_token)
        fail!(:id_token_issuer_invalid) if id_token[:iss] != ID_TOKEN_ISSUER
      end

      def verify_aud(id_token)
        fail!(:id_token_audience_invalid) if id_token[:aud] != options.client_id
      end

      def verify_nonce(id_token)
        expected_nonce = session.delete('omniauth.nonce')
        return unless expected_nonce

        fail!(:nonce_mismatch) if id_token[:nonce] != expected_nonce
      end

      def verify_at_hash(id_token)
        return unless id_token[:at_hash]

        expected_hash = generate_hash(access_token.token)
        fail!(:at_hash_mismatch) if id_token[:at_hash] != expected_hash
      end

      def verify_c_hash(id_token)
        return unless id_token[:c_hash]

        auth_code = request.params['code']
        return unless auth_code

        expected_hash = generate_hash(auth_code)
        fail!(:c_hash_mismatch) if id_token[:c_hash] != expected_hash
      end

      def generate_hash(value)
        hash = Digest::SHA256.digest(value)
        half_of_hash = hash[0, hash.length / 2]
        Base64.urlsafe_encode64(half_of_hash, padding: false)
      end

      def verify_exp(id_token)
        fail!(:id_token_expired) if id_token[:exp] < Time.now.to_i
      end

      def verify_iat(id_token)
        fail!(:id_token_issued_at_too_old) if id_token[:iat] < (Time.now.to_i - options.jwt_leeway)
      end

      def verify_auth_time(id_token)
        return unless id_token[:auth_time]

        max_age = session.delete('omniauth.max_age')
        return unless max_age

        fail!(:auth_time_too_old) if (id_token[:auth_time] + max_age.to_i) < Time.now.to_i
      end
    end
  end
end
