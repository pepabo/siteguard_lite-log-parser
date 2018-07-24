require 'siteguard_lite/log/detect'

RSpec.describe SiteguardLite::Log::Detect do
  subject { SiteguardLite::Log::Detect.new.parse(sample) }

  describe '#parse' do
    let(:sample) {
      <<~EOD
        1531397957.965300      0 192.168.0.100 TCP_MISS/000 0 GET http://example.com/?p=<script>alert(%22hello%22)</script> - DIRECT/192.168.1.100 - DETECT-STAT:WAF:RULE_SIG/PART_PARAM_VALUE|PART_GET_PARAM/p/OFFICIAL/00102001/xss-tag-1::%3cscript%3e:%3cscript%3ealert(%22hello%22)%3c/script%3e: ACTION:BLOCK: JUDGE:BLOCK:0: SEARCH-KEY:1531397957.965300.76402:
      EOD
    }

    it { expect(subject['time_epoch']).to eq '1531397957.965300' }
    it { expect(subject['conn_time']).to eq '0' }
    it { expect(subject['client_ip']).to eq '192.168.0.100' }
    it { expect(subject['file_size']).to eq '0' }
    it { expect(subject['http_method']).to eq 'GET' }
    it { expect(subject['url']).to eq 'http://example.com/?p=<script>alert(%22hello%22)</script>' }
    it { expect(subject['hierarchy_code']).to eq 'DIRECT/192.168.1.100' }
    it { expect(subject['content_type']).to eq '-' }
    it { expect(subject['detect_stat']).to eq 'DETECT-STAT:WAF:RULE_SIG/PART_PARAM_VALUE|PART_GET_PARAM/p/OFFICIAL/00102001/xss-tag-1::%3cscript%3e:%3cscript%3ealert(%22hello%22)%3c/script%3e:' }
    it { expect(subject['detect_str']).to eq '%3cscript%3e' }
    it { expect(subject['detect_str_all']).to eq '%3cscript%3ealert(%22hello%22)%3c/script%3e' }
    it { expect(subject['action']).to eq 'ACTION:BLOCK:' }
    it { expect(subject['action_str']).to eq 'BLOCK' }
    it { expect(subject['judge']).to eq 'JUDGE:BLOCK:0:' }
    it { expect(subject['judge_str']).to eq 'BLOCK' }
    it { expect(subject['monitor_url']).to eq '0' }
    it { expect(subject['search_key']).to eq 'SEARCH-KEY:1531397957.965300.76402:' }
    it { expect(subject['search_key_time_epoch']).to eq '1531397957.965300' }
    it { expect(subject['search_key_nginx_request_id']).to eq '76402' }

    describe 'detect_name' do
      context 'when RULE_SIG' do
        let(:sample) {
          <<~EOD
            1531397957.965300      0 192.168.0.100 TCP_MISS/000 0 GET http://example.com/?p=<script>alert(%22hello%22)</script> - DIRECT/10.51.100.34 - DETECT-STAT:WAF:RULE_SIG/PART_PARAM_VALUE|PART_GET_PARAM/p/OFFICIAL/00102001/xss-tag-1::%3cscript%3e:%3cscript%3ealert(%22hello%22)%3c/script%3e: ACTION:BLOCK: JUDGE:BLOCK:0: SEARCH-KEY:1531397957.965300.76402:
          EOD
        }

        it { expect(subject['detect_name']).to eq 'RULE_SIG/PART_PARAM_VALUE|PART_GET_PARAM/p/OFFICIAL/00102001/xss-tag-1' }
        it { expect(subject['detect_name_rule']).to eq 'RULE_SIG' }
        it { expect(subject['rule_sig_part']).to eq 'PART_PARAM_VALUE|PART_GET_PARAM' }
        it { expect(subject['rule_sig_name']).to eq 'p' }
        it { expect(subject['rule_sig_file']).to eq 'OFFICIAL' }
        it { expect(subject['rule_sig_id']).to eq '00102001' }
        it { expect(subject['rule_sig_signature_name']).to eq 'xss-tag-1' }
      end

      context 'WAF_FILTER' do
        # TODO
      end

      context 'RULE_URLDECODE' do
        # TODO
      end

      context 'when RULE_PARAMS_NUM' do
        let(:sample) {
          <<~EOD
            1526955182.297552   6327 192.168.0.100 TCP_MISS/000 971720 POST http://example.com/ - DIRECT/192.168.1.100 multipart/form-data DETECT-STAT:WAF:RULE_PARAMS_NUM/PART_REQBODY/3000:::8416: ACTION:BLOCK: JUDGE:BLOCK:0: SEARCH-KEY:1526955182.297552.41097:
          EOD
        }

        it { expect(subject['detect_name']).to eq 'RULE_PARAMS_NUM/PART_REQBODY/3000' }
        it { expect(subject['detect_name_rule']).to eq 'RULE_PARAMS_NUM' }
        it { expect(subject['rule_params_num_part']).to eq 'PART_REQBODY' }
        it { expect(subject['rule_params_num_threshold']).to eq '3000' }
        it { expect(subject['detect_str_all']).to eq '8416' }
      end
    end

    context 'when leading time exist' do
      # The downloaded logs have leading time, and the logs saved in the servers do not.
      subject { SiteguardLite::Log::Detect.new(leading_time: true).parse(sample) }

      let(:sample) {
        <<~EOD
          2018-07-12 21:19:17 : 1531397957.965300      0 192.168.0.100 TCP_MISS/000 0 GET http://example.com/?p=<script>alert(%22hello%22)</script> - DIRECT/10.51.100.34 - DETECT-STAT:WAF:RULE_SIG/PART_PARAM_VALUE|PART_GET_PARAM/p/OFFICIAL/00102001/xss-tag-1::%3cscript%3e:%3cscript%3ealert(%22hello%22)%3c/script%3e: ACTION:BLOCK: JUDGE:BLOCK:0: SEARCH-KEY:1531397957.965300.76402:
        EOD
      }

      it { expect(subject['time']).to eq '2018-07-12 21:19:17' }
      it { expect(subject['time_epoch']).to eq '1531397957.965300' }
    end
  end
end
