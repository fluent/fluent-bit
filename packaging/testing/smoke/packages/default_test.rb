describe package('td-agent-bit') do
  it { should be_installed }
  # TODO: check version
end

describe service('td-agent-bit') do
  it { should be_installed }
  it { should be_enabled }
  it { should be_running }
end
