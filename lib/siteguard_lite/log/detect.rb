module SiteguardLite
  module Log
    class Detect
      TIME = '(?<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'.freeze
      TIME_EPOCH = '(?<time_epoch>\d+\.\d+)'.freeze
      CONN_TIME = '(?<conn_time>\d+)'.freeze
      CLIENT_IP = '(?<client_ip>[\da-f.:]+)'.freeze
      RESULT = 'TCP_MISS\/000'.freeze
      FILE_SIZE = '(?<file_size>\d+)'.freeze
      HTTP_METHOD = '(?<http_method>[A-Z]+)'.freeze
      URL = '(?<url>[^\s]+)'.freeze
      USER = '-'.freeze
      HIERARCHY_CODE = '(?<hierarchy_code>[^\s]+)'.freeze
      CONTENT_TYPE = '(?<content_type>[^\s]+)'.freeze

      RULE_SIG = '(?<detect_name_rule>RULE_SIG)\/(?<rule_sig_part>[^\/]+)\/(?<rule_sig_name>[^\/]*+)\/(?<rule_sig_file>(?:OFFICIAL|CUSTOM))\/(?<rule_sig_id>[^\/]+)\/(?<rule_sig_signature_name>[\w\d-]+)'.freeze
      WAF_FILTER = '(?<detect_name_rule>WAF_FILTER)'.freeze
      RULE_URLDECODE = '(?<detect_name_rule>RULE_URLDECODE)'.freeze
      RULE_PARAMS_NUM = '(?<detect_name_rule>RULE_PARAMS_NUM)\/(?<rule_params_num_part>[^\/]+)\/(?<rule_params_num_threshold>\d+)'.freeze
      DETECT_NAME = "(?<detect_name>(?:#{RULE_SIG}|#{WAF_FILTER}|#{RULE_URLDECODE}|#{RULE_PARAMS_NUM}))".freeze
      DETECT_STAT = "(?<detect_stat>DETECT-STAT:WAF:#{DETECT_NAME}:(?<detect_content_type>[^:]*):(?<detect_str>[^:]*):(?<detect_str_all>[^:]+):)".freeze

      ACTION = '(?<action>ACTION:(?<action_str>[A-Z]+):)'.freeze
      JUDGE = '(?<judge>JUDGE:(?<judge_str>[A-Z]+):(?<monitor_url>0|1):)'.freeze
      SEARCH_KEY = '(?<search_key>SEARCH-KEY:(?<search_key_time_epoch>\d+\.\d+)\.(?<search_key_nginx_request_id>[^:]+):)'.freeze

      def initialize(leading_time: false)
        @leading_time = leading_time
      end

      def parse(line_str)
        if m = line_str.match(pattern)
          m.named_captures
        else
          {}
        end
      end

      private

      def pattern
        @pattern ||= if @leading_time
          /\A#{TIME} : #{pattern_parts.join('\s+')}/
        else
          /\A#{pattern_parts.join('\s+')}/
        end
      end

      def pattern_parts
        [
          TIME_EPOCH,
          CONN_TIME,
          CLIENT_IP,
          RESULT,
          FILE_SIZE,
          HTTP_METHOD,
          URL,
          USER,
          HIERARCHY_CODE,
          CONTENT_TYPE,
          DETECT_STAT,
          ACTION,
          JUDGE,
          SEARCH_KEY,
        ]
      end
    end
  end
end
