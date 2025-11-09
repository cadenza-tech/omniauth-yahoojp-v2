# frozen_string_literal: true

RSpec.describe OmniAuth::Strategies::YahoojpV2 do # rubocop:disable RSpec/SpecFilePathFormat
  let(:options) { {} }
  let(:strategy) { described_class.new('app', 'client_id', 'client_secret', options) }

  describe 'default options' do
    it 'has correct default values' do
      expect(strategy.options.name).to eq('yahoojp_v2')
      expect(strategy.options.client_options.site).to eq('https://auth.login.yahoo.co.jp')
      expect(strategy.options.client_options.authorize_url).to eq('/yconnect/v2/authorization')
      expect(strategy.options.client_options.token_url).to eq('/yconnect/v2/token')
      expect(strategy.options.scope).to eq('openid profile email')
      expect(strategy.options.pkce).to be(true)
      expect(strategy.options.jwt_leeway).to eq(600)
      expect(strategy.options.skip_jwt).to be(false)
    end
  end

  describe 'custom options' do
    context 'with custom scope' do
      let(:options) { { scope: 'profile openid' } }

      it 'uses custom scope' do
        expect(strategy.options.scope).to eq('profile openid')
      end
    end
  end

  describe '#uid' do
    let(:raw_info) { { 'sub' => 'KVNE5DZLWIY4Y57TRDLURJOOEU' } }

    before { allow(strategy).to receive(:raw_info).and_return(raw_info) }

    it 'returns the sub from raw_info' do
      expect(strategy.uid).to eq('KVNE5DZLWIY4Y57TRDLURJOOEU')
    end
  end

  describe '#info' do
    let(:raw_info) do
      {
        'sub' => 'KVNE5DZLWIY4Y57TRDLURJOOEU',
        'name' => '矢風太郎',
        'given_name' => '太郎',
        'given_name#ja-Kana-JP' => 'タロウ',
        'given_name#ja-Hani-JP' => '太郎',
        'family_name' => '矢風',
        'family_name#ja-Kana-JP' => 'ヤフウ',
        'family_name#ja-Hani-JP' => '矢風',
        'gender' => 'male',
        'zoneinfo' => 'Asia/Tokyo',
        'locale' => 'ja-JP',
        'birthdate' => '1986',
        'nickname' => 'やふうたろう',
        'picture' => 'https://dummy.img.yahoo.co.jp/example.png',
        'email' => 'yconnect@example.com',
        'email_verified' => 'true',
        'address' => {
          'country' => 'JP',
          'postal_code' => '1028282',
          'region' => '東京都',
          'locality' => '千代田区',
          'formatted' => '東京都千代田区'
        }
      }
    end

    before { allow(strategy).to receive_messages(raw_info: raw_info) }

    it 'returns correct info hash' do
      info = strategy.info
      expect(info).to eq(
        name: '矢風太郎',
        nickname: 'やふうたろう',
        first_name: '太郎',
        first_name_kana: 'タロウ',
        first_name_hani: '太郎',
        last_name: '矢風',
        last_name_kana: 'ヤフウ',
        last_name_hani: '矢風',
        gender: 'male',
        zoneinfo: 'Asia/Tokyo',
        locale: 'ja-JP',
        birth_year: 1986,
        image: 'https://dummy.img.yahoo.co.jp/example.png',
        email: 'yconnect@example.com',
        email_verified: true,
        address: {
          country: 'JP',
          postal_code: '1028282',
          region: '東京都',
          locality: '千代田区',
          formatted: '東京都千代田区'
        }
      )
    end

    it 'prunes empty values' do
      allow(strategy).to receive_messages(
        raw_info: {
          'sub' => 'KVNE5DZLWIY4Y57TRDLURJOOEU',
          'name' => '矢風太郎',
          'given_name' => '太郎',
          'given_name#ja-Kana-JP' => 'タロウ',
          'given_name#ja-Hani-JP' => '太郎',
          'family_name' => '矢風',
          'family_name#ja-Kana-JP' => 'ヤフウ',
          'family_name#ja-Hani-JP' => '矢風',
          'zoneinfo' => 'Asia/Tokyo',
          'locale' => 'ja-JP',
          'birthdate' => '1986',
          'nickname' => 'やふうたろう',
          'picture' => '',
          'email' => 'yconnect@example.com',
          'email_verified' => 'true',
          'address' => nil
        }
      )
      info = strategy.info
      expect(info).to have_key(:name)
      expect(info).to have_key(:nickname)
      expect(info).to have_key(:first_name)
      expect(info).to have_key(:first_name_kana)
      expect(info).to have_key(:first_name_hani)
      expect(info).to have_key(:last_name)
      expect(info).to have_key(:last_name_kana)
      expect(info).to have_key(:last_name_hani)
      expect(info).not_to have_key(:gender)
      expect(info).to have_key(:zoneinfo)
      expect(info).to have_key(:locale)
      expect(info).to have_key(:birth_year)
      expect(info).not_to have_key(:image)
      expect(info).to have_key(:email)
      expect(info).to have_key(:email_verified)
      expect(info).not_to have_key(:address)
    end
  end

  describe '#extra' do
    let(:raw_info) do
      {
        'sub' => 'KVNE5DZLWIY4Y57TRDLURJOOEU',
        'name' => '矢風太郎',
        'given_name' => '太郎',
        'given_name#ja-Kana-JP' => 'タロウ',
        'given_name#ja-Hani-JP' => '太郎',
        'family_name' => '矢風',
        'family_name#ja-Kana-JP' => 'ヤフウ',
        'family_name#ja-Hani-JP' => '矢風',
        'gender' => 'male',
        'zoneinfo' => 'Asia/Tokyo',
        'locale' => 'ja-JP',
        'birthdate' => '1986',
        'nickname' => 'やふうたろう',
        'picture' => 'https://dummy.img.yahoo.co.jp/example.png',
        'email' => 'yconnect@example.com',
        'email_verified' => 'true',
        'address' => {
          'country' => 'JP',
          'postal_code' => '1028282',
          'region' => '東京都',
          'locality' => '千代田区',
          'formatted' => '東京都千代田区'
        }
      }
    end
    let(:id_token_info) do
      {
        raw: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAKfQ.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6qJp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJNqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7TpdQyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoSK5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg', # rubocop:disable Layout/LineLength
        decoded: {
          'iss' => 'https://auth.login.yahoo.co.jp/yconnect/v2',
          'sub' => 'KVNE5DZLWIY4Y57TRDLURJOOEU',
          'aud' => ['dj0zaiZpPWxCUTczV01KazczNSZzPWNvbnN1bWVyc2VjcmV0Jng9NDc-'],
          'exp' => 1453618036,
          'iat' => 1453272436,
          'auth_time' => 1453271436,
          'nonce' => 'n-0S6_WzA2Mj',
          'amr' => ['pwd'],
          'at_hash' => 'SjjfaAWSdWEvSDfASCmonm',
          'c_hash' => 'LDktKdoQak3Pk0cnXxCltA'
        }
      }
    end

    before { allow(strategy).to receive_messages(raw_info: raw_info, id_token_info: id_token_info) }

    it 'returns correct extra hash' do
      extra = strategy.extra
      expect(extra).to eq(
        raw_info: {
          'sub' => 'KVNE5DZLWIY4Y57TRDLURJOOEU',
          'name' => '矢風太郎',
          'given_name' => '太郎',
          'given_name#ja-Kana-JP' => 'タロウ',
          'given_name#ja-Hani-JP' => '太郎',
          'family_name' => '矢風',
          'family_name#ja-Kana-JP' => 'ヤフウ',
          'family_name#ja-Hani-JP' => '矢風',
          'gender' => 'male',
          'zoneinfo' => 'Asia/Tokyo',
          'locale' => 'ja-JP',
          'birthdate' => '1986',
          'nickname' => 'やふうたろう',
          'picture' => 'https://dummy.img.yahoo.co.jp/example.png',
          'email' => 'yconnect@example.com',
          'email_verified' => 'true',
          'address' => {
            'country' => 'JP',
            'postal_code' => '1028282',
            'region' => '東京都',
            'locality' => '千代田区',
            'formatted' => '東京都千代田区'
          }
        },
        id_token: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAKfQ.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6qJp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJNqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7TpdQyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoSK5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg', # rubocop:disable Layout/LineLength
        id_info: {
          'iss' => 'https://auth.login.yahoo.co.jp/yconnect/v2',
          'sub' => 'KVNE5DZLWIY4Y57TRDLURJOOEU',
          'aud' => ['dj0zaiZpPWxCUTczV01KazczNSZzPWNvbnN1bWVyc2VjcmV0Jng9NDc-'],
          'exp' => 1453618036,
          'iat' => 1453272436,
          'auth_time' => 1453271436,
          'nonce' => 'n-0S6_WzA2Mj',
          'amr' => ['pwd'],
          'at_hash' => 'SjjfaAWSdWEvSDfASCmonm',
          'c_hash' => 'LDktKdoQak3Pk0cnXxCltA'
        }
      )
    end

    it 'prunes empty values' do
      allow(strategy).to receive(:id_token_info).and_return({
        raw: nil,
        decoded: ''
      })
      extra = strategy.extra
      expect(extra).to have_key(:raw_info)
      expect(extra).not_to have_key(:id_token)
      expect(extra).not_to have_key(:id_info)
    end

    context 'when skip_info is true' do
      before { allow(strategy).to receive(:skip_info?).and_return(true) }

      it 'returns correct extra hash' do
        extra = strategy.extra
        expect(extra).to eq(
          id_token: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAKfQ.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6qJp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJNqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7TpdQyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoSK5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg', # rubocop:disable Layout/LineLength
          id_info: {
            'iss' => 'https://auth.login.yahoo.co.jp/yconnect/v2',
            'sub' => 'KVNE5DZLWIY4Y57TRDLURJOOEU',
            'aud' => ['dj0zaiZpPWxCUTczV01KazczNSZzPWNvbnN1bWVyc2VjcmV0Jng9NDc-'],
            'exp' => 1453618036,
            'iat' => 1453272436,
            'auth_time' => 1453271436,
            'nonce' => 'n-0S6_WzA2Mj',
            'amr' => ['pwd'],
            'at_hash' => 'SjjfaAWSdWEvSDfASCmonm',
            'c_hash' => 'LDktKdoQak3Pk0cnXxCltA'
          }
        )
      end
    end
  end

  describe '#credentials' do
    let(:access_token) do
      instance_double(
        OAuth2::AccessToken,
        token: 'token',
        expires?: true,
        expires_at: 1234567890,
        refresh_token: 'refresh_token'
      )
    end

    before { allow(strategy).to receive(:access_token).and_return(access_token) }

    it 'returns credentials hash' do
      credentials = strategy.credentials
      expect(credentials).to include(
        token: 'token',
        expires: true,
        expires_at: 1234567890,
        refresh_token: 'refresh_token'
      )
    end

    context 'when access token does not expire' do
      let(:access_token) do
        instance_double(
          OAuth2::AccessToken,
          token: 'token',
          expires?: false,
          refresh_token: 'refresh_token'
        )
      end

      it 'does not include expires_at' do
        credentials = strategy.credentials
        expect(credentials).to include(
          token: 'token',
          expires: false,
          refresh_token: 'refresh_token'
        )
        expect(credentials).not_to have_key(:expires_at)
      end
    end

    context 'without refresh token' do
      let(:access_token) do
        instance_double(
          OAuth2::AccessToken,
          token: 'token',
          expires?: true,
          expires_at: 1234567890,
          refresh_token: nil
        )
      end

      it 'does not include refresh_token' do
        credentials = strategy.credentials
        expect(credentials).to include(
          token: 'token',
          expires: true,
          expires_at: 1234567890
        )
        expect(credentials).not_to have_key(:refresh_token)
      end
    end
  end

  describe '#raw_info' do
    let(:access_token) { instance_double(OAuth2::AccessToken, token: 'token', params: { 'id_token' => 'id_token' }) }
    let(:response) do
      instance_double(
        OAuth2::Response,
        parsed: {
          'sub' => 'KVNE5DZLWIY4Y57TRDLURJOOEU',
          'name' => '矢風太郎',
          'given_name' => '太郎',
          'given_name#ja-Kana-JP' => 'タロウ',
          'given_name#ja-Hani-JP' => '太郎',
          'family_name' => '矢風',
          'family_name#ja-Kana-JP' => 'ヤフウ',
          'family_name#ja-Hani-JP' => '矢風',
          'gender' => 'male',
          'zoneinfo' => 'Asia/Tokyo',
          'locale' => 'ja-JP',
          'birthdate' => '1986',
          'nickname' => 'やふうたろう',
          'picture' => 'https://dummy.img.yahoo.co.jp/example.png',
          'email' => 'yconnect@example.com',
          'email_verified' => 'true',
          'address' => {
            'country' => 'JP',
            'postal_code' => '1028282',
            'region' => '東京都',
            'locality' => '千代田区',
            'formatted' => '東京都千代田区'
          }
        }
      )
    end

    before do
      allow(access_token).to receive(:get).and_return(response)
      allow(strategy).to receive(:access_token).and_return(access_token)
    end

    it 'fetches user info from API' do
      expect(strategy.raw_info).to eq(
        {
          'sub' => 'KVNE5DZLWIY4Y57TRDLURJOOEU',
          'name' => '矢風太郎',
          'given_name' => '太郎',
          'given_name#ja-Kana-JP' => 'タロウ',
          'given_name#ja-Hani-JP' => '太郎',
          'family_name' => '矢風',
          'family_name#ja-Kana-JP' => 'ヤフウ',
          'family_name#ja-Hani-JP' => '矢風',
          'gender' => 'male',
          'zoneinfo' => 'Asia/Tokyo',
          'locale' => 'ja-JP',
          'birthdate' => '1986',
          'nickname' => 'やふうたろう',
          'picture' => 'https://dummy.img.yahoo.co.jp/example.png',
          'email' => 'yconnect@example.com',
          'email_verified' => 'true',
          'address' => {
            'country' => 'JP',
            'postal_code' => '1028282',
            'region' => '東京都',
            'locality' => '千代田区',
            'formatted' => '東京都千代田区'
          }
        }
      )
    end

    it 'memoizes the result' do
      2.times { strategy.raw_info }
      expect(access_token).to have_received(:get).once
    end

    context 'when skip_info is true' do
      before { allow(strategy).to receive_messages(skip_info?: true, decode_id_token: { sub: 'KVNE5DZLWIY4Y57TRDLURJOOEU' }) }

      it 'returns correct raw_info hash' do
        expect(strategy.raw_info).to eq({ 'sub' => 'KVNE5DZLWIY4Y57TRDLURJOOEU' })
      end
    end
  end

  describe '#callback_url' do
    context 'without redirect_uri option' do
      it 'builds callback url from request' do
        allow(strategy).to receive_messages(full_host: 'https://example.com', callback_path: '/auth/yahoojp_v2/callback')
        expect(strategy.callback_url).to eq('https://example.com/auth/yahoojp_v2/callback')
      end
    end

    context 'with redirect_uri option' do
      let(:options) { { redirect_uri: 'https://custom.example.com/callback' } }

      it 'uses redirect_uri option' do
        expect(strategy.callback_url).to eq('https://custom.example.com/callback')
      end
    end
  end

  describe '#authorize_params' do
    let(:request) { instance_double(Rack::Request, params: {}) }

    before { allow(strategy).to receive_messages(request: request, session: {}) }

    it 'includes default scope when not specified' do
      params = strategy.authorize_params
      expect(params[:scope]).to eq('openid profile email')
    end

    it 'includes response_type as code' do
      params = strategy.authorize_params
      expect(params[:response_type]).to eq('code')
    end

    context 'with scope in request params' do
      let(:request) { instance_double(Rack::Request, params: { 'scope' => 'openid profile' }) }

      it 'uses scope from request params' do
        params = strategy.authorize_params
        expect(params[:scope]).to eq('openid profile')
      end
    end

    context 'with state in request params' do
      let(:request) { instance_double(Rack::Request, params: { 'state' => 'af0ifjsldkj' }) }

      it 'includes state in params and stores in session' do
        params = strategy.authorize_params
        expect(params[:state]).to eq('af0ifjsldkj')
        expect(strategy.session['omniauth.state']).to eq('af0ifjsldkj')
      end
    end

    context 'with nonce in request params' do
      let(:request) { instance_double(Rack::Request, params: { 'nonce' => 'n-0S6_WzA2Mj' }) }

      it 'includes nonce in params and stores in session' do
        params = strategy.authorize_params
        expect(params[:nonce]).to eq('n-0S6_WzA2Mj')
        expect(strategy.session['omniauth.nonce']).to eq('n-0S6_WzA2Mj')
      end
    end

    context 'with prompt in request params' do
      let(:request) { instance_double(Rack::Request, params: { 'prompt' => 'consent' }) }

      it 'includes prompt in params and stores in session' do
        params = strategy.authorize_params
        expect(params[:prompt]).to eq('consent')
      end
    end

    context 'with display in request params' do
      let(:request) { instance_double(Rack::Request, params: { 'display' => 'popup' }) }

      it 'includes display in params and stores in session' do
        params = strategy.authorize_params
        expect(params[:display]).to eq('popup')
      end
    end

    context 'with max_age in request params' do
      let(:request) { instance_double(Rack::Request, params: { 'max_age' => 600 }) }

      it 'includes max_age in params and stores in session' do
        params = strategy.authorize_params
        expect(params[:max_age]).to eq(600)
      end
    end

    context 'with bail in request params' do
      let(:request) { instance_double(Rack::Request, params: { 'bail' => 1 }) }

      it 'includes bail in params and stores in session' do
        params = strategy.authorize_params
        expect(params[:bail]).to eq(1)
      end
    end
  end

  describe '#prune!' do
    it 'removes nil values from hash' do
      hash = { a: 1, b: nil, c: 'test' }
      expect(strategy.send(:prune!, hash)).to eq({ a: 1, c: 'test' })
    end

    it 'removes empty string values from hash' do
      hash = { a: 'value', b: '', c: 'another' }
      expect(strategy.send(:prune!, hash)).to eq({ a: 'value', c: 'another' })
    end

    it 'removes empty array values from hash' do
      hash = { a: [1, 2], b: [], c: ['test'] }
      expect(strategy.send(:prune!, hash)).to eq({ a: [1, 2], c: ['test'] })
    end

    it 'removes empty hash values from hash' do
      hash = { a: { x: 1 }, b: {}, c: { y: 2 } }
      expect(strategy.send(:prune!, hash)).to eq({ a: { x: 1 }, c: { y: 2 } })
    end

    it 'keeps zero values' do
      hash = { a: 0, b: nil, c: 'value' }
      expect(strategy.send(:prune!, hash)).to eq({ a: 0, c: 'value' })
    end

    it 'keeps false values' do
      hash = { a: false, b: nil, c: true }
      expect(strategy.send(:prune!, hash)).to eq({ a: false, c: true })
    end

    it 'handles nested hashes' do
      hash = { a: { x: 1, y: nil, z: '' }, b: { w: nil, x: '', y: [], z: {} }, c: { nested: { value: 'test', empty: nil } } }
      result = strategy.send(:prune!, hash)
      expect(result).to eq({ a: { x: 1 }, c: { nested: { value: 'test' } } })
    end

    it 'modifies the original hash' do
      hash = { a: 1, b: nil, c: 'test' }
      result = strategy.send(:prune!, hash)
      expect(hash.object_id).to eq(result.object_id)
      expect(hash).to eq({ a: 1, c: 'test' })
    end
  end

  describe '#empty?' do
    it 'returns true for nil values' do
      expect(strategy.send(:empty?, nil)).to be(true)
    end

    it 'returns true for empty strings' do
      expect(strategy.send(:empty?, '')).to be(true)
    end

    it 'returns true for empty arrays' do
      expect(strategy.send(:empty?, [])).to be(true)
    end

    it 'returns true for empty hashes' do
      expect(strategy.send(:empty?, {})).to be(true)
    end

    it 'returns false for non-empty strings' do
      expect(strategy.send(:empty?, 'value')).to be(false)
    end

    it 'returns false for non-empty arrays' do
      expect(strategy.send(:empty?, [1, 2, 3])).to be(false)
    end

    it 'returns false for non-empty hashes' do
      expect(strategy.send(:empty?, { key: 'value' })).to be(false)
    end

    it 'returns false for zero values' do
      expect(strategy.send(:empty?, 0)).to be(false)
    end

    it 'returns false for false values' do
      expect(strategy.send(:empty?, false)).to be(false)
    end

    it 'returns false for objects that do not respond to empty?' do
      expect(strategy.send(:empty?, 123)).to be(false)
    end
  end

  describe '#id_token_info' do
    let(:access_token) { instance_double(OAuth2::AccessToken, params: { 'id_token' => 'id_token' }) }
    let(:decoded_token) { instance_double(JSON::JWT) }

    before do
      allow(strategy).to receive_messages(
        access_token: access_token,
        skip_info?: false,
        decode_id_token: decoded_token
      )
      allow(strategy).to receive(:verify_id_token)
    end

    it 'returns id token info' do
      expect(strategy.send(:id_token_info)).to eq({ raw: 'id_token', decoded: decoded_token })
    end

    context 'when @id_token_info is already set' do
      before { strategy.instance_variable_set(:@id_token_info, { raw: 'cached_id_token', decoded: decoded_token }) }

      it 'returns cached id token info' do
        expect(strategy.send(:id_token_info)).to eq({ raw: 'cached_id_token', decoded: decoded_token })
      end
    end

    context 'when id_token is not present' do
      let(:access_token) { instance_double(OAuth2::AccessToken, params: {}) }

      it 'returns empty id token info' do
        expect(strategy.send(:id_token_info)).to eq({ raw: nil, decoded: nil })
      end
    end

    context 'when skip_info is true' do
      before { allow(strategy).to receive(:skip_info?).and_return(true) }

      it 'returns id token info with raw token and nil decoded data' do
        expect(strategy.send(:id_token_info)).to eq({ raw: 'id_token', decoded: nil })
      end
    end

    context 'when skip_jwt is true' do
      let(:options) { { skip_jwt: true } }

      it 'returns id token info' do
        result = strategy.send(:id_token_info)
        expect(result).to eq({ raw: 'id_token', decoded: decoded_token })
        expect(strategy).not_to have_received(:verify_id_token)
      end
    end
  end

  describe '#verify_id_token' do
    let(:id_token) { instance_double(JSON::JWS, kid: 'kid') }
    let(:jwk) { instance_double(JSON::JWK) }

    before do
      allow(strategy).to receive(:fetch_jwk).and_return(jwk)
      allow(strategy).to receive(:verify_signature)
      allow(strategy).to receive(:verify_claims)
    end

    it 'fetches JWK and verifies signature and claims' do
      strategy.send(:verify_id_token, id_token)
      expect(strategy).to have_received(:fetch_jwk).with('kid')
      expect(strategy).to have_received(:verify_signature).with(id_token, jwk)
      expect(strategy).to have_received(:verify_claims).with(id_token)
    end

    context 'when verification fails' do
      before do
        allow(strategy).to receive(:verify_claims).and_raise(StandardError)
        allow(strategy).to receive(:fail!)
      end

      it 'calls fail!' do
        strategy.send(:verify_id_token, id_token)
        expect(strategy).to have_received(:fail!).with(:id_token_verification_failed, StandardError)
      end
    end
  end

  describe '#fetch_jwk' do
    let(:jwk) { instance_double(JSON::JWK) }

    before { allow(JSON::JWK::Set::Fetcher).to receive(:fetch).and_return(jwk) }

    it 'fetches JWK from JWKS_URL' do
      result = strategy.send(:fetch_jwk, 'kid')
      expect(JSON::JWK::Set::Fetcher).to have_received(:fetch).with(
        'https://auth.login.yahoo.co.jp/yconnect/v2/jwks',
        kid: 'kid'
      )
      expect(result).to eq(jwk)
    end

    context 'when fetch fails' do
      before do
        allow(JSON::JWK::Set::Fetcher).to receive(:fetch).and_raise(StandardError)
        allow(strategy).to receive(:fail!)
      end

      it 'calls fail!' do
        strategy.send(:fetch_jwk, 'kid')
        expect(strategy).to have_received(:fail!).with(:jwk_fetch_failed, StandardError)
      end
    end
  end

  describe '#verify_signature' do
    let(:id_token) { instance_double(JSON::JWS) }
    let(:jwk) { instance_double(JSON::JWK) }

    it 'verifies id_token signature with jwk' do
      allow(id_token).to receive(:verify!)
      strategy.send(:verify_signature, id_token, jwk)
      expect(id_token).to have_received(:verify!).with(jwk)
    end

    context 'when signature verification fails' do
      before do
        allow(id_token).to receive(:verify!).and_raise(StandardError)
        allow(strategy).to receive(:fail!)
      end

      it 'calls fail!' do
        strategy.send(:verify_signature, id_token, jwk)
        expect(strategy).to have_received(:fail!).with(:id_token_signature_invalid, StandardError)
      end
    end
  end

  describe '#verify_claims' do
    let(:id_token) { instance_double(JSON::JWS) }

    before do
      allow(strategy).to receive(:verify_iss)
      allow(strategy).to receive(:verify_aud)
      allow(strategy).to receive(:verify_nonce)
      allow(strategy).to receive(:verify_at_hash)
      allow(strategy).to receive(:verify_c_hash)
      allow(strategy).to receive(:verify_exp)
      allow(strategy).to receive(:verify_iat)
      allow(strategy).to receive(:verify_auth_time)
    end

    it 'calls all claim verification methods' do
      strategy.send(:verify_claims, id_token)
      expect(strategy).to have_received(:verify_iss).with(id_token)
      expect(strategy).to have_received(:verify_aud).with(id_token)
      expect(strategy).to have_received(:verify_nonce).with(id_token)
      expect(strategy).to have_received(:verify_at_hash).with(id_token)
      expect(strategy).to have_received(:verify_c_hash).with(id_token)
      expect(strategy).to have_received(:verify_exp).with(id_token)
      expect(strategy).to have_received(:verify_iat).with(id_token)
      expect(strategy).to have_received(:verify_auth_time).with(id_token)
    end
  end

  describe '#verify_iss' do
    let(:id_token) { { iss: 'https://auth.login.yahoo.co.jp/yconnect/v2' } }

    before { allow(strategy).to receive(:fail!) }

    it 'does not call fail!' do
      strategy.send(:verify_iss, id_token)
      expect(strategy).not_to have_received(:fail!)
    end

    context 'when id_token is issued by an invalid issuer' do
      let(:id_token) { { iss: 'https://invalid-issuer.com' } }

      it 'calls fail!' do
        strategy.send(:verify_iss, id_token)
        expect(strategy).to have_received(:fail!).with(:id_token_issuer_invalid)
      end
    end
  end

  describe '#verify_aud' do
    let(:id_token) { { aud: 'client_id' } }

    before { allow(strategy).to receive(:fail!) }

    it 'does not call fail!' do
      strategy.send(:verify_aud, id_token)
      expect(strategy).not_to have_received(:fail!)
    end

    context 'when id_token is issued to an invalid audience' do
      let(:id_token) { { aud: 'invalid_client_id' } }

      it 'calls fail!' do
        strategy.send(:verify_aud, id_token)
        expect(strategy).to have_received(:fail!).with(:id_token_audience_invalid)
      end
    end
  end

  describe '#verify_nonce' do
    let(:id_token) { { nonce: 'n-0S6_WzA2Mj' } }
    let(:session) { { 'omniauth.nonce' => 'n-0S6_WzA2Mj' } }

    before do
      allow(strategy).to receive(:session).and_return(session)
      allow(strategy).to receive(:fail!)
    end

    it 'does not call fail!' do
      strategy.send(:verify_nonce, id_token)
      expect(strategy).not_to have_received(:fail!)
      expect(session).not_to have_key('omniauth.nonce')
    end

    context 'when nonce does not match' do
      let(:id_token) { { nonce: 'invalid_nonce' } }

      it 'calls fail!' do
        strategy.send(:verify_nonce, id_token)
        expect(strategy).to have_received(:fail!).with(:nonce_mismatch)
      end
    end

    context 'when id_token does not have nonce' do
      let(:session) { {} }

      it 'does not call fail!' do
        strategy.send(:verify_nonce, id_token)
        expect(strategy).not_to have_received(:fail!)
      end
    end
  end

  describe '#verify_at_hash' do
    let(:access_token) { instance_double(OAuth2::AccessToken) }
    let(:id_token) { { at_hash: 'hash' } }

    before do
      allow(access_token).to receive(:token)
      allow(strategy).to receive_messages(access_token: access_token, generate_hash: 'hash')
      allow(strategy).to receive(:fail!)
    end

    it 'does not call fail!' do
      strategy.send(:verify_at_hash, id_token)
      expect(strategy).not_to have_received(:fail!)
    end

    context 'when at_hash does not match' do
      let(:id_token) { { at_hash: 'invalid_hash' } }

      it 'calls fail!' do
        strategy.send(:verify_at_hash, id_token)
        expect(strategy).to have_received(:fail!).with(:at_hash_mismatch)
      end
    end

    context 'when id_token does not have at_hash' do
      let(:id_token) { {} }

      it 'does not call fail!' do
        strategy.send(:verify_at_hash, id_token)
        expect(strategy).not_to have_received(:fail!)
      end
    end
  end

  describe '#verify_c_hash' do
    let(:request) { instance_double(Rack::Request, params: { 'code' => 'code' }) }
    let(:id_token) { { c_hash: 'hash' } }

    before do
      allow(strategy).to receive_messages(request: request, generate_hash: 'hash')
      allow(strategy).to receive(:fail!)
    end

    it 'does not call fail!' do
      strategy.send(:verify_c_hash, id_token)
      expect(strategy).not_to have_received(:fail!)
    end

    context 'when c_hash does not match' do
      let(:id_token) { { c_hash: 'invalid_hash' } }

      it 'calls fail!' do
        strategy.send(:verify_c_hash, id_token)
        expect(strategy).to have_received(:fail!).with(:c_hash_mismatch)
      end
    end

    context 'when id_token does not have c_hash' do
      let(:id_token) { {} }

      it 'does not call fail!' do
        strategy.send(:verify_c_hash, id_token)
        expect(strategy).not_to have_received(:fail!)
      end
    end

    context 'when request params does not have code' do
      let(:request) { instance_double(Rack::Request, params: {}) }
      let(:id_token) { { c_hash: 'hash' } }

      it 'does not call fail!' do
        strategy.send(:verify_c_hash, id_token)
        expect(strategy).not_to have_received(:fail!)
      end
    end
  end

  describe '#generate_hash' do
    it 'generates a correct hash for a given input value' do
      value = 'abcd'
      hash = strategy.send(:generate_hash, value)
      expect(hash).to eq('iNQmb9TmM40TuEX88olXnQ')
    end
  end

  describe '#verify_exp' do
    let(:id_token) { { exp: Time.now.to_i + 3600 } }

    before { allow(strategy).to receive(:fail!) }

    it 'does not call fail!' do
      strategy.send(:verify_exp, id_token)
      expect(strategy).not_to have_received(:fail!)
    end

    context 'when id_token is expired' do
      let(:id_token) { { exp: Time.now.to_i - 3600 } }

      it 'calls fail!' do
        strategy.send(:verify_exp, id_token)
        expect(strategy).to have_received(:fail!).with(:id_token_expired)
      end
    end
  end

  describe '#verify_iat' do
    let(:id_token) { { iat: Time.now.to_i } }

    before { allow(strategy).to receive(:fail!) }

    it 'does not call fail!' do
      strategy.send(:verify_iat, id_token)
      expect(strategy).not_to have_received(:fail!)
    end

    context 'when id_token is issued too long ago' do
      let(:id_token) { { iat: Time.now.to_i - 601 } }

      it 'calls fail!' do
        strategy.send(:verify_iat, id_token)
        expect(strategy).to have_received(:fail!).with(:id_token_issued_at_too_old)
      end
    end

    context 'when jwt_leeway is set to a large value' do
      let(:options) { { jwt_leeway: 1000 } }
      let(:id_token) { { iat: Time.now.to_i - 601 } }

      it 'does not call fail!' do
        strategy.send(:verify_iat, id_token)
        expect(strategy).not_to have_received(:fail!)
      end
    end
  end

  describe '#verify_auth_time' do
    let(:session) { { 'omniauth.max_age' => 300 } }
    let(:id_token) { { auth_time: Time.now.to_i - 100 } }

    before do
      allow(strategy).to receive(:session).and_return(session)
      allow(strategy).to receive(:fail!)
    end

    it 'does not call fail!' do
      strategy.send(:verify_auth_time, id_token)
      expect(strategy).not_to have_received(:fail!)
      expect(session).not_to have_key('omniauth.max_age')
    end

    context 'when auth_time exceeds max_age' do
      let(:id_token) { { auth_time: Time.now.to_i - 400 } }

      it 'calls fail!' do
        strategy.send(:verify_auth_time, id_token)
        expect(strategy).to have_received(:fail!).with(:auth_time_too_old)
      end
    end

    context 'when id_token does not have auth_time' do
      let(:id_token) { {} }

      it 'does not call fail!' do
        strategy.send(:verify_auth_time, id_token)
        expect(strategy).not_to have_received(:fail!)
      end
    end

    context 'when max_age is not set in session' do
      let(:session) { {} }

      it 'does not call fail!' do
        strategy.send(:verify_auth_time, id_token)
        expect(strategy).not_to have_received(:fail!)
      end
    end
  end
end
