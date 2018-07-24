module SiteguardLite
  module Log
    class CLI
      def initialize(options)
        @type = options.delete(:type)
        @format = options.delete(:format)
        @parser = SiteguardLiteLogParser.new(@type, options)
      end

      def run
        while line = STDIN.gets
          line.chomp!
          result = @parser.parse(line)
          puts format(result)
        end
      end

      private

      def format(h)
        case @format
        when 'ltsv'
          require 'ltsv'
          LTSV.dump(h)
        else
          raise ArgumentError, "Unexpected output format: #{@format}"
        end
      end
    end
  end
end
