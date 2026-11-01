class Testd < Formula
  desc "Local dev domain manager: stable HTTPS names from any dev environment"
  homepage "https://github.com/testd/testd"
  url "https://github.com/testd/testd/archive/refs/tags/v#{version}.tar.gz"
  sha256 "TODO"
  license "ISC"
  head "https://github.com/testd/testd.git", branch: "master"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: ".")
  end

  service do
    run [opt_bin/"testd", "host"]
    keep_alive true
    log_path var/"log/testd.log"
    error_log_path var/"log/testd.err"
  end

  test do
    assert_match "testd", shell_output("#{bin}/testd --help")
    system bin/"testd", "doctor", "--json"
  end
end
