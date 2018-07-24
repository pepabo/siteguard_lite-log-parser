# SiteguardLite::Log::Parser

A log parser for SiteGuard Lite WAF.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'siteguard_lite-log-parser'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install siteguard_lite-log-parser

## Usage

```ruby
require 'siteguard_lite/log/parser'

parser = SiteguardLiteLogParser.new(log_type)
log = parser.parse(log_str)
```

The supported log types are following.

- `detect`: Parse a `detect.log` format string

The `new` function accepts a optional hash with following keys.

- `leading_time`: A time string at the beginning of the line (optional, default: `false`)
  - SiteGuard Liteの管理画面からダウンロードしたログファイルには行頭に`YYYY-MM-DD hh:mm:ss : `という形式の日時文字列が付いているので、このオプションが必要です。

### detect.log

The parse result have the following keys.

- `time`: クライアントから接続された時刻です。`YYYY-MM-DD hh:mm:ss`形式で表示します。(optional)
- `time_epoch`: クライアントから接続された時刻です。エポックタイム (1970/01/01 00:00:00(UTC)) からの秒数をミリ秒単位で表示します。
- `conn_time`: クライアントとの接続時間をミリ秒単位で表示します。
- `client_ip`: クライアントの IP アドレスを表示します。
- `file_size`: 転送したファイルのサイズです。
- `http_method`: HTTP の要求メソッド (GET, POST 等) です。
- `url`: 接続先の URL です。
- `hierarchy_code`: "DIRECT/本製品をインストールしているサーバーの IP アドレス" を表示します。
- `content_type`: 送受信するファイルの Content-Type を表示します。利用できない場合は "-" となります。
- `detect_stat`: 検出情報。`DETECT-STAT:WAF:[detect_name]::[detect_str]:[detect_str_all]:`を表示します。
- `detect_name`: 検出名。以下のいずれかです。
  - シグネチャ検査: `RULE_SIG/[rule_sig_part]/[rule_sig_name]/[rule_sig_file]/[rule_sig_id]/[rule_sig_signature_name]`
    - `detect_name_rule`: RULE_SIG
    - `rule_sig_part`: 検出箇所
    - `rule_sig_name`: 名前。パラメータ変数、ヘッダフィールド名を表示します。
    - `rule_sig_file`: シグネチャファイル。OFFICIAL(トラステッド・シグネチャ)、CUSTOM(カスタム・シグネチャ) のいずれかです。
    - `rule_sig_id`: シグネチャID
    - `rule_sig_signature_name`: シグネチャ名
  - フィルタ: `WAF_FILTER/[IP アドレス]` **(NOT SUPPORTED)**
  - URL デコードエラー: `RULE_URLDECODE/[検出箇所]/[名前]` **(NOT SUPPORTED)**
  - パラメータ数の上限値の制限: `RULE_PARAMS_NUM/[rule_params_num_part/[rule_params_num_threshold]`
    - `detect_name_rule`: RULE_PARAMS_NUM
    - `rule_params_num_part`: 検出箇所
    - `rule_params_num_threshold`: パラメータ数の上限値
- `detect_str`: 検出文字列
- `detect_str_all`: 検出文字列(全体)
- `action`: 動作。`ACTION:[action_str]:`を表示します。
- `action_str`: 動作。MONITOR, BLOCK, FILTERのいずれかです。
- `judge`: `JUDGE:[judge_str]:[monitor_url]:`を表示します。
- `judge_str`: 判定。MONITOR, BLOCK, FILTERのいずれかです。
- `monitor_url`: 監視 URL の設定。0(監視 URL に該当しない)、1(監視 URL に該当する)のいずれかです。
- `search_key`: 検索キー。`SEARCH-KEY:[search_key_time_epock.seach_key_nginx_request_id]:`を表示します。
- `search_key_time_epoch`: 時刻(エポックタイム)
- `search_key_nginx_request_id`: nginx リクエスト ID

## siteguard_lite-log

The command line tool to parse logs. This tool output as LTSV format.

```
cat detect.log | siteguard_lite-log
```

Usage:
```
$ siteguard_lite-log --help
Usage: siteguard_lite-log [options]
        --type VAL                   Specify log type. (default: detect)
        --leading-time               The log have the time string at heading of the line
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/pepabo/siteguard_lite-log-parser.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
