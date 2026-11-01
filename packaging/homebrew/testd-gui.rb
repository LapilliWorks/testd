cask "testd-gui" do
  version "0.1.0"
  sha256 "TODO"

  url "https://github.com/testd/testd/releases/download/v#{version}/Testd-#{version}.dmg"
  name "Testd"
  desc "Tray app for the testd local dev domain manager"
  homepage "https://github.com/testd/testd"

  depends_on macos: ">= :ventura"

  app "Testd.app"
end
