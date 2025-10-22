%global pypi_name kylin-ai-cryptojacking-detect

Name:           kylin-ai-cryptojacking-detect
Version:        0.1.1
Release:        1%{?dist}
Summary:        Multi-layer cryptominer detector (L1/L2/L3)
License:        MIT
URL:            https://example.com
Source0:        %{pypi_name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros

# 运行时依赖（根据你的代码）
Requires:       python3
Requires:       python3dist(pyyaml)
Requires:       python3dist(psutil)
Requires:       python3dist(pandas)

%description
Multi-layer cryptominer detection tool: L1 system signals, L2 process scan, L3 memory forensics. Installs `miner-sentinel` CLI.

%prep
%setup -q -n %{pypi_name}-%{version}

%build
%pyproject_wheel

%install
%pyproject_install
# 把 Python 包文件列表保存到宏 %{pyproject_files}
%pyproject_save_files msentinel_cli miner_sentinel_l1 miner_sentinel_l2 miner_sentinel_l3

%check
# 可选：跑你的自测
# python3 -c "import msentinel_cli"

%files -n %{name} -f %{pyproject_files}
%license LICENSE
%doc README.md README README.rst readme.md
%{_bindir}/miner-sentinel

%changelog
* Wed Oct 22 2025 You <you@example.com> - 0.1.1-1
- Include YAML/JSON/PKL resources; install console script; rpm repackage.
