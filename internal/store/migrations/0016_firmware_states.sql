-- 0016: the Dell firmware states the other way round (docs/tech_doc.md §38). A Dell
-- "Installed-" member is what the device runs; a "Current-" member is the image the BMC
-- holds in its firmware store (OEM status AvailableForInstallation), which 0014 took for
-- the running version. On rows that hold both, running and the stored image swap; the
-- release date and the document time came from the stored image's member and are
-- cleared, so the next scan reads the running member's document. The "appeared" change
-- row of such a component names the running version; later change rows are history and
-- stay as recorded. lc_installed becomes stored.
UPDATE firmware_changes
   SET after = (SELECT c.lc_installed FROM firmware_components c
                 WHERE c.server_id = firmware_changes.server_id
                   AND c.component_id = firmware_changes.component_id
                   AND c.fqdd = firmware_changes.fqdd)
 WHERE field = 'running' AND before = ''
   AND EXISTS (SELECT 1 FROM firmware_components c
                WHERE c.server_id = firmware_changes.server_id
                  AND c.component_id = firmware_changes.component_id
                  AND c.fqdd = firmware_changes.fqdd
                  AND c.lc_installed <> '' AND c.running = firmware_changes.after);

UPDATE firmware_components
   SET running = lc_installed, lc_installed = running, release_date = NULL, doc_read_at = NULL
 WHERE lc_installed <> '';

ALTER TABLE firmware_components RENAME COLUMN lc_installed TO stored;
