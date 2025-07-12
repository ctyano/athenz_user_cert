class athenz_user_cert < Formula
  desc "CLI to obtain Athenz User Certificate"
  homepage "https://github.com/ctyano/athenz_user_cert"
  license "GPL-3.0-only"

  depends_on "jq" => :build # For parsing GitHub API responses

  def install
    # Determine architecture
    arch = case Hardware::CPU.arch
    when :arm64
      "arm64"
    else
      "amd64"
    end

    os = "darwin"
    repo = "ctyano/athenz_user_cert"
    version = Utils.safe_popen_read("bash", "-c", <<~EOS).strip
      curl -s https://api.github.com/repos/ctyano/athenz_user_cert/releases/latest |
      jq -r .tag_name | sed -e 's/.*v\([0-9]*.[0-9]*.[0-9]*\).*/\1/g'
    EOS
    asset_name = "athenz_user_cert_#{version}_#{os}_#{arch}.tar.gz"

    ohai "Fetching latest release asset for #{repo}..."

    # Get the asset download URL from GitHub API
    download_url = Utils.safe_popen_read("bash", "-c", <<~EOS).strip
      curl -s https://api.github.com/repos/#{repo}/releases/latest |
      jq -r '.assets[] | select(.name == "#{asset_name}") | .browser_download_url'
    EOS

    if download_url.empty?
      odie "Failed to get download URL for asset: #{asset_name}"
    end

    ohai "Downloading #{asset_name} from: #{download_url}"

    # Download and extract
    system "curl", "-L", "-o", "athenz_user_cert.tar.gz", download_url
    system "tar", "-xzf", "athenz_user_cert.tar.gz"

    # Move the binary into Homebrew’s bin directory
    bin.install "athenz_user_cert"
  end

  test do
    system "#{bin}/athenz_user_cert", "version"
    assert_match "athenz_user_cert", shell_output("#{bin}/athenz_user_cert version")
  end
end

