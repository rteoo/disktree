//! The scanned tree.

use std::path::{Path, PathBuf};

use crate::classify::{Category, Reclaim};

pub type FileKey = (u64, u64);

/// What a node represents on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    Directory,
    File,
    Symlink,
    /// Sockets, fifos and devices: addressable, but not space.
    Other,
}

impl NodeKind {
    pub const fn is_dir(self) -> bool {
        matches!(self, Self::Directory)
    }
}

/// How a node's importance is measured.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Metric {
    /// Bytes, apparent or on-disk depending on [`crate::scan::ScanOptions`].
    #[default]
    Bytes,
    /// Number of files at or beneath the node.
    Files,
}

impl Metric {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Bytes => "size",
            Self::Files => "files",
        }
    }

    #[must_use]
    pub const fn toggled(self) -> Self {
        match self {
            Self::Bytes => Self::Files,
            Self::Files => Self::Bytes,
        }
    }
}

/// One entry in the scanned tree.
///
/// Totals and direct figures are both kept: `own_bytes` and `own_files` are
/// what sits directly in a directory, `bytes` and `files` are the subtree
/// totals the treemap draws. The selection line needs both, and keeping them means
/// no second traversal when one of them is displayed.
#[derive(Clone, Debug)]
pub struct Node {
    pub name: Box<str>,
    pub kind: NodeKind,
    /// Subtree total: direct contents plus every descendant.
    pub bytes: u64,
    /// Bytes of the leaf entries directly in this directory, or this file's
    /// own size. Derived by [`aggregate`].
    pub own_bytes: u64,
    /// Files at or beneath this node; `1` for a file.
    pub files: u64,
    /// Files directly in this directory; `1` for a file. Derived by
    /// [`aggregate`].
    pub own_files: u64,
    /// Directories at or beneath this node; `1` for a directory.
    pub dirs: u64,
    /// `(device, inode)` for files, used to de-duplicate hardlinks.
    pub inode: Option<FileKey>,
    /// The directory could not be read; its contents are unknown.
    pub read_error: bool,
    /// Newest write time at or beneath this node, in Unix seconds; `0` when
    /// unknown. Derived for directories by [`aggregate`].
    pub modified: i64,
    /// What kind of data this is, for colour. Set by [`crate::classify`].
    pub category: Category,
    /// Why this space can be had back, if it can. Set by
    /// [`crate::classify`]; inherited by everything beneath.
    pub reclaim: Option<Reclaim>,
    /// Children, ordered by [`Metric`] value, descending.
    pub children: Vec<Self>,
}

impl Node {
    /// A directory with no children yet.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "`impl Into<Box<str>>` cannot be called in a const fn"
    )]
    pub fn directory(name: impl Into<Box<str>>) -> Self {
        Self {
            name: name.into(),
            kind: NodeKind::Directory,
            bytes: 0,
            own_bytes: 0,
            files: 0,
            own_files: 0,
            dirs: 1,
            inode: None,
            read_error: false,
            modified: 0,
            category: Category::Other,
            reclaim: None,
            children: Vec::new(),
        }
    }

    /// A leaf entry.
    pub fn entry(
        name: impl Into<Box<str>>,
        kind: NodeKind,
        bytes: u64,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            bytes,
            own_bytes: bytes,
            files: u64::from(kind == NodeKind::File),
            own_files: u64::from(kind == NodeKind::File),
            dirs: 0,
            inode: None,
            read_error: false,
            modified: 0,
            category: Category::Other,
            reclaim: None,
            children: Vec::new(),
        }
    }

    pub const fn is_dir(&self) -> bool {
        self.kind.is_dir()
    }

    /// The value a treemap should weight this node by.
    pub const fn value(&self, metric: Metric) -> u64 {
        match metric {
            Metric::Bytes => self.bytes,
            Metric::Files => self.files,
        }
    }

    /// The child with this name, if there is one.
    pub fn child_named(&self, name: &str) -> Option<&Self> {
        self.children.iter().find(|child| &*child.name == name)
    }

    pub fn child(&self, index: usize) -> Option<&Self> {
        self.children.get(index)
    }

    /// Follow `crumbs` from this node. Crumbs are child indices, so they stay
    /// valid across re-sorting only for the tree they were produced from.
    pub fn resolve(&self, crumbs: &[usize]) -> Option<&Self> {
        let mut node = self;
        for &index in crumbs {
            node = node.children.get(index)?;
        }
        Some(node)
    }

    /// The chain of nodes ending at `crumbs`, including this node.
    pub fn resolve_chain<'a>(&'a self, crumbs: &[usize]) -> Vec<&'a Self> {
        let mut chain = vec![self];
        let mut node = self;
        for &index in crumbs {
            match node.children.get(index) {
                Some(child) => {
                    chain.push(child);
                    node = child;
                }
                None => break,
            }
        }
        chain
    }

    /// Index of the largest child, used to pick a useful descent target.
    pub const fn largest_child(&self) -> Option<usize> {
        if self.children.is_empty() {
            None
        } else {
            Some(0)
        }
    }

    /// Depth of the deepest descendant.
    pub fn depth(&self) -> u32 {
        self.children
            .iter()
            .map(Self::depth)
            .max()
            .map_or(0, |deepest| deepest + 1)
    }

    /// Breadth-first search for the first node whose name contains `needle`
    /// (case-insensitive), returning its crumbs and the node.
    pub fn find(&self, needle: &str) -> Option<(Vec<usize>, &Self)> {
        let needle = needle.to_lowercase();
        if needle.is_empty() {
            return None;
        }
        let mut queue = vec![(Vec::new(), self)];
        while let Some((crumbs, node)) = queue.pop() {
            for (index, child) in node.children.iter().enumerate() {
                if child.name.to_lowercase().contains(&needle) {
                    let found: Vec<usize> = crumbs
                        .iter()
                        .copied()
                        .chain(std::iter::once(index))
                        .collect();
                    return Some((found, child));
                }
                if child.is_dir() && !child.children.is_empty() {
                    let mut next = crumbs.clone();
                    next.push(index);
                    queue.push((next, child));
                }
            }
        }
        None
    }
}

/// Recompute `bytes`, `files`, `dirs` and the direct totals bottom-up, then
/// order children by `metric`, largest first.
///
/// `bytes` and `files` are the subtree totals; `own_bytes` and `own_files` are
/// the direct contents, derived from the leaf children rather than tracked
/// separately. Deriving them is what keeps the two consistent: hardlink
/// de-duplication rewrites a leaf's weight, and every total above it —
/// including its parent's "direct" figure — follows without a second pass.
pub fn aggregate(node: &mut Node, metric: Metric) {
    if !node.is_dir() {
        node.bytes = node.own_bytes;
        node.files = node.own_files;
        node.dirs = 0;
        return;
    }

    let mut bytes = 0;
    let mut files = 0;
    let mut own_bytes = 0;
    let mut own_files = 0;
    let mut dirs: u64 = 1;
    let mut modified = 0;
    for child in &mut node.children {
        aggregate(child, metric);
        modified = modified.max(child.modified);
        bytes += child.bytes;
        files += child.files;
        dirs += child.dirs;
        if !child.is_dir() {
            own_bytes += child.bytes;
            own_files += child.files;
        }
    }
    node.bytes = bytes;
    node.files = files;
    node.own_bytes = own_bytes;
    node.own_files = own_files;
    node.dirs = dirs;
    node.modified = modified;

    // Largest first: a treemap lays out big tiles best, and the order is what
    // makes "descend into the largest child" meaningful.
    node.children.sort_by(|left, right| {
        right
            .value(metric)
            .cmp(&left.value(metric))
            .then_with(|| left.name.cmp(&right.name))
    });
}

/// Absolute path of the node at `crumbs` beneath a scanned root.
pub fn path_of(root_path: &Path, root: &Node, crumbs: &[usize]) -> PathBuf {
    let mut path = root_path.to_path_buf();
    let mut node = root;
    for &index in crumbs {
        match node.children.get(index) {
            Some(child) => {
                path.push(&*child.name);
                node = child;
            }
            None => break,
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(name: &str, bytes: u64) -> Node {
        Node::entry(name, NodeKind::File, bytes)
    }

    #[test]
    fn aggregate_derives_totals_and_orders_children() {
        let mut root = Node::directory("root");
        let mut nested = Node::directory("child");
        nested.children.push(leaf("deep", 7));
        root.children.push(nested);
        root.children.push(leaf("direct", 5));
        root.children.push(leaf("small", 9));

        aggregate(&mut root, Metric::Bytes);
        assert_eq!(root.own_bytes, 5 + 9, "direct leaves only");
        assert_eq!(root.bytes, 5 + 9 + 7);
        assert_eq!(root.files, 3);
        assert_eq!(root.own_files, 2);
        assert_eq!(root.dirs, 2);
        assert_eq!(child_named(&root, "child").own_bytes, 7);
        assert_eq!(&*root.children[0].name, "small", "9 bytes, largest first");
        assert_eq!(&*root.children[2].name, "direct");

        // A file's own size is what it weighs; aggregates never invent more.
        let mut single = leaf("solo", 3);
        aggregate(&mut single, Metric::Bytes);
        assert_eq!(single.bytes, 3);
        assert_eq!(single.own_bytes, 3);
        assert_eq!(single.files, 1);
        assert_eq!(single.dirs, 0);
    }

    fn child_named<'a>(node: &'a Node, name: &str) -> &'a Node {
        node.children
            .iter()
            .find(|child| &*child.name == name)
            .unwrap_or_else(|| panic!("no child named {name}"))
    }

    #[test]
    fn aggregate_can_rank_by_file_count() {
        let mut root = Node::directory("root");
        let mut many = Node::directory("many");
        for index in 0..5 {
            many.children.push(leaf(&format!("f{index}"), 1));
        }
        root.children.push(many);
        root.children.push(leaf("huge", 10_000));

        aggregate(&mut root, Metric::Bytes);
        assert_eq!(&*root.children[0].name, "huge");
        aggregate(&mut root, Metric::Files);
        assert_eq!(&*root.children[0].name, "many");
        assert_eq!(root.children[0].files, 5);
    }

    #[test]
    fn resolve_walks_child_indices() {
        let mut root = Node::directory("root");
        let mut nested = Node::directory("child");
        nested.children.push(leaf("deep", 1));
        root.children.push(nested);

        assert!(root.resolve(&[]).is_some());
        assert_eq!(root.resolve(&[0, 0]).map(|n| &*n.name), Some("deep"));
        assert!(root.resolve(&[0, 1]).is_none());
        assert_eq!(root.resolve_chain(&[0, 0]).len(), 3);
    }

    #[test]
    fn path_of_joins_names_beneath_the_root() {
        let mut root = Node::directory("root");
        let mut nested = Node::directory("child");
        nested.children.push(leaf("deep", 1));
        root.children.push(nested);

        let path = path_of(Path::new("/home/tobi"), &root, &[0, 0]);
        assert_eq!(path, PathBuf::from("/home/tobi/child/deep"));
    }

    #[test]
    fn largest_child_is_the_first_child_because_children_are_sorted() {
        let mut root = Node::directory("root");
        root.children.push(leaf("big", 10));
        root.children.push(leaf("small", 1));
        assert_eq!(root.largest_child(), Some(0));
        assert_eq!(Node::directory("empty").largest_child(), None);
    }

    #[test]
    fn find_reports_crumbs_and_is_case_insensitive() {
        let mut root = Node::directory("root");
        let mut target = Node::directory("target");
        target.children.push(leaf("needle-file", 1));
        root.children.push(target);

        let (crumbs, found) = root.find("NEEDLE").expect("found");
        assert_eq!(crumbs, vec![0, 0]);
        assert_eq!(&*found.name, "needle-file");
        assert!(root.find("").is_none());
        assert!(root.find("absent").is_none());
    }

    #[test]
    fn depth_counts_edges() {
        let mut root = Node::directory("root");
        let mut nested = Node::directory("child");
        nested.children.push(leaf("deep", 1));
        root.children.push(nested);
        assert_eq!(root.depth(), 2);
        assert_eq!(leaf("x", 0).depth(), 0);
    }
}
