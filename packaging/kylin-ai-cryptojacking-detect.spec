Name:           kylin-ai-cryptojacking-detect
Version:        0.1.0
Release:        %autorelease
Summary:        Cryptojacking detection suite (L1/L2/L3)
License:        MIT
URL:            https://example.com

# 把连字符转成下划线，匹配 sdist 的命名
%global srcname %{lua: n = rpm.expand("%{name}"); print((n:gsub("%-","_")))}

Source0:        %{srcname}-%{version}.tar.gz
BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros
# 按需增减运行依赖
Requires:       python3dist(psutil)
Requires:       python3dist(pandas)

%description
Single package shipping L1/L2/L3 modules and the CLI.

%prep
%autosetup -n %{srcname}-%{version}

%build
%pyproject_wheel

%install
%pyproject_install
# 如果你的 CLI 在 src/msentinel_cli/cli.py（从你日志看是这样）：
%pyproject_save_files msentinel_cli miner_sentinel_l1 miner_sentinel_l2 miner_sentinel_l3
# 若你的 CLI 真在 src/cli.py，请把上一行的 msentinel_cli 改成 cli


%files -f %{pyproject_files}
%{_bindir}/miner-sentinel
%doc readme.md
%{_bindir}/miner-sentinel
# 如果你还保留了 LICENSE：
%license LICENSE
