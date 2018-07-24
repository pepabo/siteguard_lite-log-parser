require 'siteguard_lite/log/detect'

class SiteguardLiteLogParser
  def initialize(type, options = {})
    @type = type
    @options = options

    @parser = get_parser(type)
  end

  def parse(line_str)
    @parser.parse(line_str)
  end

  private

  def get_parser(type)
    case type
    when 'detect'
      SiteguardLite::Log::Detect.new(leading_time: leading_time)
    else
      raise ArgumentError, "Unexpected log type: #{type}"
    end
  end

  def leading_time
    @options[:leading_time]
  end
end
