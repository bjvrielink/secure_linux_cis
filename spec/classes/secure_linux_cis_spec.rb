require 'spec_helper'

describe 'secure_linux_cis' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'os' => {
            'architecture' => 'amd64',
            'name' => 'RedHat',
            'release' => { 'major' => 7 },
          },
        )
      end

      it { is_expected.to compile }
    end
  end
end
