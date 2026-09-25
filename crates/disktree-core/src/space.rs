//! Free space on the volume a path lives on.
//!
//! This is what makes "amount of crap I found" a real number rather than an
//! estimate: the app measures the volume before and after a removal, and shows
//! the projection while marking.

use std::io;
use std::path::{Path, PathBuf};

/// A volume's capacity in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpaceInfo {
    /// Total size of the volume.
    pub total: u64,
    /// Free blocks, including the reserve only root may write to.
    pub free: u64,
    /// Free blocks this user may actually write; what `df -h` reports.
    pub available: u64,
}

impl SpaceInfo {
    /// Space in use, computed from `free` rather than `available` so the figure
    /// does not jump when a reserve is opened to root.
    pub const fn used(&self) -> u64 {
        self.total.saturating_sub(self.free)
    }

    /// Share of the volume in use, `0.0..=1.0`.
    pub fn used_fraction(&self) -> f32 {
        if self.total == 0 {
            0.0
        } else {
            (self.used() as f64 / self.total as f64) as f32
        }
    }

    /// Free space after `bytes` are removed, saturating at the volume size and
    /// never counting the same byte twice.
    #[must_use]
    pub fn after_removing(&self, bytes: u64) -> Self {
        let available = self.available.saturating_add(bytes).min(self.total);
        let free = self.free.saturating_add(bytes).min(self.total);
        Self {
            total: self.total,
            free,
            available,
        }
    }
}

/// Read the space on the volume containing `path`.
#[cfg(windows)]
pub fn space_info(path: &Path) -> io::Result<SpaceInfo> {
    crate::windows::space_info(path)
}

/// Read the space on the volume containing `path`.
#[cfg(not(windows))]
pub fn space_info(path: &Path) -> io::Result<SpaceInfo> {
    let stat = rustix::fs::statvfs(path)?;
    // `f_frsize` is the fragment size the block counts are expressed in;
    // `f_bsize` is only a hint for I/O. Some filesystems report zero for
    // `f_frsize`, so fall back rather than claiming a zero-sized volume.
    let block = if stat.f_frsize == 0 {
        stat.f_bsize
    } else {
        stat.f_frsize
    };
    Ok(SpaceInfo {
        total: stat.f_blocks.saturating_mul(block),
        free: stat.f_bfree.saturating_mul(block),
        available: stat.f_bavail.saturating_mul(block),
    })
}

/// The volume a path is on, as Windows names it: `C:\`, a share, or the
/// folder a volume is mounted on.
#[cfg(windows)]
pub fn device_for(path: &Path) -> Option<String> {
    crate::windows::volume_root(path).map(|root| root.display().to_string())
}

/// The device a path's filesystem is mounted from, such as
/// `/dev/nvme0n1p2`: the mount with the longest prefix of `path` in
/// `/proc/self/mounts`. `None` where that table cannot be read.
#[cfg(not(any(target_os = "macos", windows)))]
pub fn device_for(path: &Path) -> Option<String> {
    let table = std::fs::read_to_string("/proc/self/mounts").ok()?;
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    device_in(&table, &path)
}

/// [`device_for`] over a given mount table, for testing.
pub fn device_in(table: &str, path: &Path) -> Option<String> {
    table
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let device = fields.next()?;
            // Spaces in mount points are escaped as \040.
            let mount = fields.next()?.replace("\\040", " ");
            path.starts_with(&mount)
                .then(|| (mount.len(), device.to_string()))
        })
        .max_by_key(|(length, _)| *length)
        .map(|(_, device)| device)
}

/// One line of the mount table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    /// What is mounted: a device, or a name like `tmpfs` or `systemd-1`.
    pub source: String,
    pub point: PathBuf,
    pub fstype: String,
    pub options: String,
}

/// Parse `/proc/self/mounts`.
pub fn parse_mounts(table: &str) -> Vec<Mount> {
    table
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let source = fields.next()?.to_string();
            // Spaces in mount points are escaped as \040.
            let point = PathBuf::from(fields.next()?.replace("\\040", " "));
            let fstype = fields.next()?.to_string();
            let options = fields.next().unwrap_or_default().to_string();
            Some(Mount {
                source,
                point,
                fstype,
                options,
            })
        })
        .collect()
}

/// Mount points below `root` that are not part of `root`'s volume, which a
/// scan of that volume must not enter.
///
/// "The volume" is the mount *source*, not the device number: btrfs gives
/// every subvolume its own `st_dev`, so `/home` on Omarchy looks like a
/// different filesystem from `/` though it is the same disk. Everything
/// else is left out: pseudo filesystems (`/proc`, `/sys`), tmpfs, other
/// disks, network shares, and automount points — entering one of those
/// would mount a NAS just to measure it. Snapshot subvolumes are left out
/// too, because every file in them shares its blocks with the live one and
/// counting them would count the disk twice.
pub fn foreign_mounts(mounts: &[Mount], root: &Path) -> Vec<PathBuf> {
    let Some(own) = mounts
        .iter()
        .filter(|mount| root.starts_with(&mount.point))
        .max_by_key(|mount| mount.point.as_os_str().len())
    else {
        return Vec::new();
    };
    mounts
        .iter()
        .filter(|mount| mount.point != root && mount.point.starts_with(root))
        .filter(|mount| {
            mount.source != own.source
                || mount.fstype != own.fstype
                || is_snapshot(mount)
        })
        .map(|mount| mount.point.clone())
        .collect()
}

fn is_snapshot(mount: &Mount) -> bool {
    let named = mount
        .point
        .file_name()
        .is_some_and(|name| name == ".snapshots");
    named
        || mount.options.split(',').any(|option| {
            option.starts_with("subvol=") && option.contains("snapshots")
        })
}

/// The top of the disk `path` lives on.
///
/// The shortest mount point above it with the same source. On Omarchy the home directory is the `@home`
/// subvolume at `/home`, and the disk is `/`; with a separate home disk it
/// would be `/home`.
pub fn volume_root(mounts: &[Mount], path: &Path) -> Option<PathBuf> {
    let own = mounts
        .iter()
        .filter(|mount| path.starts_with(&mount.point))
        .max_by_key(|mount| mount.point.as_os_str().len())?;
    mounts
        .iter()
        .filter(|mount| {
            mount.source == own.source
                && mount.fstype == own.fstype
                && path.starts_with(&mount.point)
        })
        .min_by_key(|mount| mount.point.as_os_str().len())
        .map(|mount| mount.point.clone())
}

/// [`volume_root`] for this machine.
#[cfg(not(any(target_os = "macos", windows)))]
pub fn volume_root_for(path: &Path) -> Option<PathBuf> {
    let table = std::fs::read_to_string("/proc/self/mounts").ok()?;
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    volume_root(&parse_mounts(&table), &path)
}

/// The top of the volume `path` lives on: its drive, such as `C:\`.
#[cfg(windows)]
pub fn volume_root_for(path: &Path) -> Option<PathBuf> {
    crate::windows::volume_root(path)
}

/// [`foreign_mounts`] for this machine; `None` when the mount table cannot
/// be read, so the caller can fall back to comparing devices.
#[cfg(not(windows))]
pub fn foreign_mounts_for(root: &Path) -> Option<Vec<PathBuf>> {
    let table = std::fs::read_to_string("/proc/self/mounts").ok()?;
    Some(foreign_mounts(&parse_mounts(&table), root))
}

/// The mount points in what macOS's `mount` prints.
///
/// One per line: `/dev/disk3s5 on /System/Volumes/Data (apfs, local, …)`.
/// The point is
/// between the first ` on ` and the last ` (`, so a name with spaces or
/// brackets in it survives.
pub fn parse_macos_mounts(output: &str) -> Vec<PathBuf> {
    output
        .lines()
        .filter_map(|line| {
            let (_, rest) = line.split_once(" on ")?;
            let (point, _) = rest.rsplit_once(" (")?;
            Some(PathBuf::from(point))
        })
        .collect()
}

/// Where the Data volume is mounted on macOS.
///
/// Since Catalina `/` is a read-only system volume, and everything the user
/// can write — `/Users`,
/// `/Applications`, `/Library`, `/private`, … — lives on the Data volume,
/// joined into `/` by firmlinks. The two report the same device, and
/// `/Users` and `/System/Volumes/Data/Users` are the same inode.
pub const MACOS_DATA_VOLUME: &str = "/System/Volumes/Data";

/// Directories under `root` a scan must never enter, whatever the volume
/// rules say, given where `root` really is (`canonical`).
///
/// On macOS: the Data volume's second mount, which is every firmlinked
/// directory again under another name, so walking it counts the disk twice;
/// and `/Network`, an automount point that would reach for a server. The
/// paths are returned in `root`'s own spelling, because that is how the walk
/// names what it finds.
pub fn never_scanned(root: &Path, canonical: &Path) -> Vec<PathBuf> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    [MACOS_DATA_VOLUME, "/Network"]
        .iter()
        .filter_map(|skip| Path::new(skip).strip_prefix(canonical).ok())
        .filter(|below| !below.as_os_str().is_empty())
        .map(|below| root.join(below))
        .collect()
}

/// The top of the disk `path` lives on: its mount point, from `statfs`.
///
/// The Data volume answers `/System/Volumes/Data`, but the disk a user
/// thinks of is `/`, which shows the same files under the names Finder uses
/// and adds the system volume beside them.
#[cfg(target_os = "macos")]
pub fn volume_root_for(path: &Path) -> Option<PathBuf> {
    let stat = rustix::fs::statfs(path).ok()?;
    let mount = PathBuf::from(c_chars(&stat.f_mntonname));
    if mount.as_os_str().is_empty() {
        return None;
    }
    Some(if mount == Path::new(MACOS_DATA_VOLUME) {
        PathBuf::from("/")
    } else {
        mount
    })
}

/// The device a path's filesystem is mounted from, such as
/// `/dev/disk3s5`, from `statfs`.
#[cfg(target_os = "macos")]
pub fn device_for(path: &Path) -> Option<String> {
    // `/` is a snapshot of the system volume (`disk3s1s1`); name the disk
    // the user's files are on instead, which is what the meter measures.
    let path = if path == Path::new("/") {
        Path::new(MACOS_DATA_VOLUME)
    } else {
        path
    };
    let stat = rustix::fs::statfs(path).ok()?;
    let device = c_chars(&stat.f_mntfromname);
    (!device.is_empty()).then_some(device)
}

/// A NUL-terminated C string field as text.
#[cfg(target_os = "macos")]
fn c_chars(field: &[std::ffi::c_char]) -> String {
    let bytes: Vec<u8> = field
        .iter()
        .take_while(|&&byte| byte != 0)
        .map(|&byte| byte as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Nothing to leave out by path on Windows.
///
/// There, the only way into another volume below `root` is a folder that
/// volume is mounted on, which is a reparse point the walk treats as a link
/// and does not enter unless links are followed; other drives are separate
/// trees altogether.
#[cfg(windows)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the Option is the Unix answer when the mount table is missing"
)]
pub const fn foreign_mounts_for(_root: &Path) -> Option<Vec<PathBuf>> {
    Some(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OMARCHY: &str = "\
sys /sys sysfs rw 0 0
run /run tmpfs rw 0 0
/dev/mapper/root / btrfs rw,subvolid=256,subvol=/@ 0 0
/dev/mapper/root /home btrfs rw,subvolid=257,subvol=/@home 0 0
/dev/mapper/root /var/log btrfs rw,subvolid=258,subvol=/@log 0 0
/dev/mapper/root /.snapshots btrfs rw,subvolid=260,subvol=/@snapshots 0 0
/dev/nvme0n1p1 /boot vfat rw 0 0
systemd-1 /mnt/nas-home autofs rw,direct 0 0
tmpfs /tmp tmpfs rw 0 0
portal /run/user/1000/doc fuse.portal rw 0 0
";

    #[test]
    fn a_volume_includes_its_subvolumes_and_nothing_else() {
        let mounts = parse_mounts(OMARCHY);
        let mut foreign = foreign_mounts(&mounts, Path::new("/"));
        foreign.sort();
        let expected: Vec<PathBuf> = [
            "/.snapshots",
            "/boot",
            "/mnt/nas-home",
            "/run",
            "/run/user/1000/doc",
            "/sys",
            "/tmp",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        assert_eq!(foreign, expected, "/home and /var/log are the same disk");
    }

    #[test]
    fn the_whole_disk_is_the_top_of_the_home_volume() {
        let mounts = parse_mounts(OMARCHY);
        let root = volume_root(&mounts, Path::new("/home/tobi"));
        assert_eq!(root, Some(PathBuf::from("/")), "@home is on the root disk");
        let separate = parse_mounts(
            "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /home ext4 rw 0 0\n",
        );
        let root = volume_root(&separate, Path::new("/home/tobi"));
        assert_eq!(root, Some(PathBuf::from("/home")), "a separate home disk");
    }

    #[test]
    fn a_home_scan_has_no_foreign_mounts_here() {
        let mounts = parse_mounts(OMARCHY);
        assert!(foreign_mounts(&mounts, Path::new("/home/tobi")).is_empty());
    }

    #[test]
    fn the_device_is_the_longest_matching_mount() {
        let table = "\
/dev/nvme0n1p2 / btrfs rw 0 0
tmpfs /tmp tmpfs rw 0 0
/dev/sda1 /home/tobi/big\\040disk ext4 rw 0 0
";
        let device = |path: &str| device_in(table, Path::new(path));
        assert_eq!(device("/home/tobi").as_deref(), Some("/dev/nvme0n1p2"));
        assert_eq!(device("/tmp/x").as_deref(), Some("tmpfs"));
        assert_eq!(
            device("/home/tobi/big disk/a").as_deref(),
            Some("/dev/sda1"),
            "escaped spaces in mount points"
        );
    }

    #[test]
    fn macos_mount_points_keep_spaces_and_brackets() {
        let output = "\
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
devfs on /dev (devfs, local, nobrowse)
/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse)
map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)
/dev/disk5s1 on /Volumes/My Disk (2) (apfs, local, nodev, nosuid)
//tobi@nas/share on /Volumes/share on nas (smbfs, nodev, nosuid)
";
        let points: Vec<PathBuf> = [
            "/",
            "/dev",
            MACOS_DATA_VOLUME,
            "/System/Volumes/Data/home",
            "/Volumes/My Disk (2)",
            "/Volumes/share on nas",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        assert_eq!(parse_macos_mounts(output), points);
    }

    #[test]
    fn only_macos_skips_the_data_volume_and_in_the_roots_spelling() {
        let skipped = never_scanned(Path::new("/"), Path::new("/"));
        let below_system =
            never_scanned(Path::new("/System/"), Path::new("/System"));
        let inside =
            never_scanned(Path::new("/Users/tobi"), Path::new("/Users/tobi"));
        let itself = never_scanned(
            Path::new(MACOS_DATA_VOLUME),
            Path::new(MACOS_DATA_VOLUME),
        );
        if cfg!(target_os = "macos") {
            assert_eq!(
                skipped,
                vec![PathBuf::from(MACOS_DATA_VOLUME), "/Network".into()]
            );
            assert_eq!(
                below_system,
                vec![PathBuf::from("/System/Volumes/Data")]
            );
        } else {
            assert!(skipped.is_empty() && below_system.is_empty());
        }
        assert!(inside.is_empty());
        assert!(itself.is_empty(), "asking for it by name scans it");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn the_home_disk_on_macos_is_the_root_and_has_a_device() {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let home = home.expect("HOME is set");
        assert_eq!(volume_root_for(&home), Some(PathBuf::from("/")));
        let device = device_for(Path::new("/")).expect("a device");
        assert!(device.starts_with("/dev/disk"), "{device}");
    }

    #[test]
    fn a_real_volume_reports_plausible_numbers() {
        let temp = std::env::temp_dir();
        let space = space_info(&temp).expect("temp dir has a volume");
        assert!(space.total > 0, "{space:?}");
        assert!(space.free <= space.total, "{space:?}");
        assert!(space.available <= space.free, "{space:?}");
        assert!((0.0..=1.0).contains(&space.used_fraction()), "{space:?}");
    }

    #[test]
    fn a_missing_path_reports_the_io_error() {
        let error = space_info(Path::new("/definitely/not/here"))
            .expect_err("no volume");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn projecting_removal_cannot_exceed_the_volume() {
        let space = SpaceInfo {
            total: 1000,
            free: 100,
            available: 100,
        };
        let after = space.after_removing(50);
        assert_eq!(after.available, 150);
        assert_eq!(after.free, 150);
        assert_eq!(after.total, 1000);

        let capped = space.after_removing(10_000);
        assert_eq!(capped.available, 1000);
        assert_eq!(capped.used(), 0);
        assert!((capped.used_fraction() - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn used_fraction_handles_an_empty_volume_report() {
        let space = SpaceInfo::default();
        assert!((space.used_fraction() - 0.0).abs() < f32::EPSILON);
    }
}
