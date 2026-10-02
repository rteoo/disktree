# Windows release preparation

```powershell
.\prepare-release-windows.ps1 -Tag v0.10.1 -DryRun
.\prepare-release-windows.ps1 -Tag v0.10.1
```

The helper requires clean `main` at `origin/main`, runs `cargo xtask test`, and
builds the statically linked x86_64 Windows ZIP plus SHA-256. Linux, macOS,
ARM, signing, and notarization remain required release gates on native hosts.
