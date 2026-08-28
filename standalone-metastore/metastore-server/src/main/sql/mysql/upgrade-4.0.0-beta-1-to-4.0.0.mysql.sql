SELECT 'Upgrading MetaStore schema from 4.0.0-beta-1 to 4.0.0' AS MESSAGE;

-- HIVE-24815: Remove "IDXS" Table from Metastore Schema
DROP TABLE `INDEX_PARAMS`;
DROP TABLE `IDXS`;

-- HIVE-27827
DROP INDEX UNIQUEPARTITION ON PARTITIONS;
CREATE UNIQUE INDEX UNIQUEPARTITION ON PARTITIONS (TBL_ID, PART_NAME);
-- NDB binds the Hopsworks PARTITIONS_FK1 cascade FK to PARTITIONS_N49 and refuses
-- to drop the index (error 1553), unlike InnoDB which rebinds to another candidate.
-- Drop the FK first and re-add it bound to the new UNIQUEPARTITION (TBL_ID, ...) prefix.
ALTER TABLE PARTITIONS DROP FOREIGN KEY PARTITIONS_FK1;
DROP INDEX PARTITIONS_N49 on PARTITIONS;
ALTER TABLE PARTITIONS ADD CONSTRAINT PARTITIONS_FK1 FOREIGN KEY (TBL_ID) REFERENCES TBLS (TBL_ID) ON DELETE CASCADE ON UPDATE RESTRICT;

-- These lines need to be last.  Insert any changes above.
UPDATE VERSION SET SCHEMA_VERSION='4.0.0', VERSION_COMMENT='Hive release version 4.0.0' where VER_ID=1;
SELECT 'Finished upgrading MetaStore schema from 4.0.0-beta-1 to 4.0.0' AS MESSAGE;
