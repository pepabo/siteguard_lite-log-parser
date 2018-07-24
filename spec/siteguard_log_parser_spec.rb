require 'siteguard_lite_log_parser'

RSpec.describe SiteguardLiteLogParser do
  describe 'unknown log' do
    subject { SiteguardLiteLogParser.new('unknown') }
    it { expect { subject }.to raise_error ArgumentError }
  end

  describe 'detect.log' do
    subject { SiteguardLiteLogParser.new('detect') }
    it { is_expected.to be_instance_of SiteguardLiteLogParser }
  end
end
