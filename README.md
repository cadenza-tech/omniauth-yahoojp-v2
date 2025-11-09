# OmniauthYahoojpV2

[![License](https://img.shields.io/github/license/cadenza-tech/omniauth-yahoojp-v2?label=License&labelColor=343B42&color=blue)](https://github.com/cadenza-tech/omniauth-yahoojp-v2/blob/main/LICENSE.txt) [![Tag](https://img.shields.io/github/tag/cadenza-tech/omniauth-yahoojp-v2?label=Tag&logo=github&labelColor=343B42&color=2EBC4F)](https://github.com/cadenza-tech/omniauth-yahoojp-v2/blob/main/CHANGELOG.md) [![Release](https://github.com/cadenza-tech/omniauth-yahoojp-v2/actions/workflows/release.yml/badge.svg)](https://github.com/cadenza-tech/omniauth-yahoojp-v2/actions?query=workflow%3Arelease) [![Test](https://github.com/cadenza-tech/omniauth-yahoojp-v2/actions/workflows/test.yml/badge.svg)](https://github.com/cadenza-tech/omniauth-yahoojp-v2/actions?query=workflow%3Atest) [![Lint](https://github.com/cadenza-tech/omniauth-yahoojp-v2/actions/workflows/lint.yml/badge.svg)](https://github.com/cadenza-tech/omniauth-yahoojp-v2/actions?query=workflow%3Alint)

Yahoo! JAPAN strategy for OmniAuth.

- [Installation](#installation)
- [Usage](#usage)
  - [Rails Configuration with Devise](#rails-configuration-with-devise)
  - [Configuration Options](#configuration-options)
  - [Auth Hash](#auth-hash)
- [Changelog](#changelog)
- [Contributing](#contributing)
- [License](#license)
- [Code of Conduct](#code-of-conduct)
- [Sponsor](#sponsor)

## Installation

Install the gem and add to the application's Gemfile by executing:

```bash
bundle add omniauth-yahoojp-v2
```

If bundler is not being used to manage dependencies, install the gem by executing:

```bash
gem install omniauth-yahoojp-v2
```

## Usage

### Rails Configuration with Devise

Add the following to `config/initializers/devise.rb`:

```ruby
# config/initializers/devise.rb
Devise.setup do |config|
  config.omniauth :yahoojp_v2, ENV['YAHOOJP_CLIENT_ID'], ENV['YAHOOJP_CLIENT_SECRET']
end
```

Add the OmniAuth callbacks routes to `config/routes.rb`:

```ruby
# config/routes.rb
Rails.application.routes.draw do
  devise_for :users, controllers: { omniauth_callbacks: 'users/omniauth_callbacks' }
end
```

Add the OmniAuth configuration to your Devise model:

```ruby
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :omniauthable, omniauth_providers: [:yahoojp_v2]
end
```

### Configuration Options

You can configure several options:

```ruby
# config/initializers/devise.rb
Devise.setup do |config|
  config.omniauth :yahoojp_v2, ENV['YAHOOJP_CLIENT_ID'], ENV['YAHOOJP_CLIENT_SECRET'],
    {
      scope: 'openid profile email address', # Specify OAuth scopes
      callback_path: '/custom/yahoojp_v2/callback', # Custom callback path
      prompt: 'consent', # Optional: force consent screen
      display: 'popup', # Optional: auth page display mode
      max_age: 600, # Optional: max seconds since last auth
      bail: true # Optional: redirect to app on consent denial instead of Yahoo! top
    }
end
```

Available scopes:

- `openid` - Required for ID token (includes user identifier)
- `profile` - Access to user's profile
- `email` - Access to user's email address
- `address` - Access to user's address

### Auth Hash

After successful authentication, the auth hash will be available in `request.env['omniauth.auth']`:

```ruby
{
  provider: 'yahoojp_v2',
  uid: 'FQBSQOIDGW5PV4NHAAUY7BWAMU',
  info: {
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
  },
  credentials: {
    token: 'SlAV32hkKG',
    expires: true,
    expires_at: 1453618036,
    refresh_token: '8xLOxBtZp8'
  },
  extra: {
    raw_info: {
      sub: 'FQBSQOIDGW5PV4NHAAUY7BWAMU',
      name: '矢風太郎',
      given_name: '太郎',
      'given_name#ja-Kana-JP': 'タロウ',
      'given_name#ja-Hani-JP': '太郎',
      family_name: '矢風',
      'family_name#ja-Kana-JP': 'ヤフウ',
      'family_name#ja-Hani-JP': '矢風',
      gender: 'male',
      zoneinfo: 'Asia/Tokyo',
      locale: 'ja-JP',
      birthdate: '1986',
      nickname: 'やふうたろう',
      picture: 'https://dummy.img.yahoo.co.jp/example.png',
      email: 'yconnect@example.com',
      email_verified: 'true',
      address: {
        country: 'JP',
        postal_code: '1028282',
        region: '東京都',
        locality: '千代田区',
        formatted: '東京都千代田区'
      }
    },
    id_token: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAKfQ.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6qJp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJNqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7TpdQyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoSK5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg',
    id_info: {
      iss: 'https://auth.login.yahoo.co.jp/yconnect/v2',
      sub: 'KVNE5DZLWIY4Y57TRDLURJOOEU',
      aud: ['dj0zaiZpPWxCUTczV01KazczNSZzPWNvbnN1bWVyc2VjcmV0Jng9NDc-'],
      exp: 1453618036,
      iat: 1453272436,
      auth_time: 1453271436,
      nonce: 'n-0S6_WzA2Mj',
      amr: ['pwd'],
      at_hash: 'SjjfaAWSdWEvSDfASCmonm',
      c_hash: 'LDktKdoQak3Pk0cnXxCltA'
    }
  }
}
```

## Changelog

See [CHANGELOG.md](https://github.com/cadenza-tech/omniauth-yahoojp-v2/blob/main/CHANGELOG.md).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/cadenza-tech/omniauth-yahoojp-v2. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/cadenza-tech/omniauth-yahoojp-v2/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://github.com/cadenza-tech/omniauth-yahoojp-v2/blob/main/LICENSE.txt).

## Code of Conduct

Everyone interacting in the OmniauthYahoojpV2 project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/cadenza-tech/omniauth-yahoojp-v2/blob/main/CODE_OF_CONDUCT.md).

## Sponsor

You can sponsor this project on [Patreon](https://patreon.com/CadenzaTech).
