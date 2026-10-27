# Homebrew formula for Matthew-Eucaristo/homebrew-tap (Formula/lately.rb).
# Builds from the tagged source tarball. Bump `url` and `sha256` per release;
# see RELEASING.md.
class Lately < Formula
  desc "What just happened on my Mac? A classified timeline from logs macOS keeps"
  homepage "https://github.com/Matthew-Eucaristo/lately"
  url "https://github.com/Matthew-Eucaristo/lately/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_WITH_SHA256_OF_THE_TAG_TARBALL"
  license "MIT"
  head "https://github.com/Matthew-Eucaristo/lately.git", branch: "main"

  depends_on "go" => :build
  depends_on :macos

  def install
    system "go", "build", *std_go_args(ldflags: "-X main.version=#{version}")
  end

  def caveats
    <<~EOS
      lately keeps one small file of salted hashes so it can mark new things
      as NEW: ~/Library/Application Support/lately/baseline.v1.json
      Remove it with `lately forget` before `brew uninstall lately`, or run
      with --no-baseline to never create it.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/lately --version")
    assert_match "persist.launch_agent", shell_output("#{bin}/lately rules")
    assert_match "No baseline", shell_output("HOME=#{testpath} #{bin}/lately forget")
  end
end
