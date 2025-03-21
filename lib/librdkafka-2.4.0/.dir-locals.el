((nil
  (compile-command . "LC_ALL=C make -C $(git rev-parse --show-toplevel) -kw -j"))
 (c-mode
  (c-file-style . "linux")
  (tab-width . 8)
  (indent-tabs-mode . nil))
)

(if (file-exists-p (concat (dir-locals-find-file "./") "TAGS"))
    (visit-tags-table (concat (dir-locals-find-file "./") "TAGS")))
