SELECT 'Upgrading MetaStore schema from 3.0.0.14 to 3.0.0' AS MESSAGE;

-- Bridge from the Hopsworks-specific version 3.0.0.14 to the standard Apache Hive 3.0.0
-- version string so that the standard upgrade chain (3.0.0 -> 3.1.0 -> ... -> 4.1.0) can
-- proceed, and converge the Hopsworks schema divergences that the standard scripts and
-- the upstream JDO mappings assume are present.

-- The Hopsworks 3.0 schema replaced string locations with SDS/inode references:
-- CTLGS.LOCATION_URI and DBS.DB_LOCATION_URI do not exist, but upstream MCatalog and
-- MDatabase select them. Restore them; the catalog placeholder 'TBD' is replaced with
-- the warehouse root by HMSHandler.createDefaultCatalog on first startup, and database
-- locations are backfilled from the SDS rows the Hopsworks schema links via DBS.SD_ID.
-- Guarded like the rest of this file: VERSION is written only on the last line, and
-- metastore-db-job.yaml retries migrate.sh, so an interruption re-enters here from the top.
SET @_sql = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='CTLGS' AND COLUMN_NAME='LOCATION_URI')=0, 'ALTER TABLE CTLGS ADD LOCATION_URI varchar(4000) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL DEFAULT ''TBD''', 'SELECT 1');
PREPARE _s FROM @_sql;
EXECUTE _s;
DEALLOCATE PREPARE _s;
SET @_sql = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='DBS' AND COLUMN_NAME='DB_LOCATION_URI')=0, 'ALTER TABLE DBS ADD DB_LOCATION_URI varchar(4000) CHARACTER SET latin1 COLLATE latin1_bin', 'SELECT 1');
PREPARE _s FROM @_sql;
EXECUTE _s;
DEALLOCATE PREPARE _s;
-- Keyed on SD_ID, the backfill's source: the drops below remove it, and keying on the
-- target would silently skip the backfill instead of failing loudly.
SET @_sql = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='DBS' AND COLUMN_NAME='SD_ID')=1, 'UPDATE DBS D JOIN SDS S ON D.SD_ID = S.SD_ID SET D.DB_LOCATION_URI = S.LOCATION', 'SELECT 1');
PREPARE _s FROM @_sql;
EXECUTE _s;
DEALLOCATE PREPARE _s;
-- DBS.SD_ID is nullable in the Hopsworks 3.0 schema; rows without an SDS link get the
-- same 'TBD' placeholder as CTLGS so the NOT NULL constraint below cannot fail.
UPDATE DBS SET DB_LOCATION_URI = 'TBD' WHERE DB_LOCATION_URI IS NULL;
ALTER TABLE DBS MODIFY DB_LOCATION_URI varchar(4000) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL;

-- Now that the locations live in CTLGS.LOCATION_URI / DBS.DB_LOCATION_URI, retire the
-- Hopsworks SDS/inode references. They must not survive the upgrade: Hive 4.1 knows nothing
-- about them, so it neither populates nor maintains them, while the NDB engine keeps
-- enforcing their ON DELETE CASCADE. Deleting an inode in HopsFS would still cascade into
-- SDS, and from SDS on into DBS and CTLGS, silently destroying metadata behind the
-- metastore's back.
--
-- Order matters: the referencing FKs (DBS.SD_ID, CTLGS.SD_ID) go before the columns they
-- are defined on, and INODE_SDS_FK goes before the SDS inode columns.

-- DBS.SD_ID -> SDS.SD_ID (ON DELETE CASCADE)
SET @_sql = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='DBS' AND CONSTRAINT_NAME='DB_SD_FK' AND CONSTRAINT_TYPE='FOREIGN KEY')=1, 'ALTER TABLE `DBS` DROP FOREIGN KEY `DB_SD_FK`', 'SELECT 1');
PREPARE _s FROM @_sql;
EXECUTE _s;
DEALLOCATE PREPARE _s;
SET @_sql = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='DBS' AND COLUMN_NAME='SD_ID')=1, 'ALTER TABLE `DBS` DROP COLUMN `SD_ID`', 'SELECT 1');
PREPARE _s FROM @_sql;
EXECUTE _s;
DEALLOCATE PREPARE _s;

-- CTLGS.SD_ID -> SDS.SD_ID (ON DELETE CASCADE)
SET @_sql = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='CTLGS' AND CONSTRAINT_NAME='CTLGS_SD_FK' AND CONSTRAINT_TYPE='FOREIGN KEY')=1, 'ALTER TABLE `CTLGS` DROP FOREIGN KEY `CTLGS_SD_FK`', 'SELECT 1');
PREPARE _s FROM @_sql;
EXECUTE _s;
DEALLOCATE PREPARE _s;
SET @_sql = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='CTLGS' AND COLUMN_NAME='SD_ID')=1, 'ALTER TABLE `CTLGS` DROP COLUMN `SD_ID`', 'SELECT 1');
PREPARE _s FROM @_sql;
EXECUTE _s;
DEALLOCATE PREPARE _s;

-- SDS (PARTITION_ID, PARENT_ID, NAME) -> hops.hdfs_inodes (ON DELETE CASCADE)
SET @_sql = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='SDS' AND CONSTRAINT_NAME='INODE_SDS_FK' AND CONSTRAINT_TYPE='FOREIGN KEY')=1, 'ALTER TABLE `SDS` DROP FOREIGN KEY `INODE_SDS_FK`', 'SELECT 1');
PREPARE _s FROM @_sql;
EXECUTE _s;
DEALLOCATE PREPARE _s;
SET @_sql = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='SDS' AND COLUMN_NAME='PARTITION_ID')=1, 'ALTER TABLE `SDS` DROP COLUMN `PARTITION_ID`', 'SELECT 1');
PREPARE _s FROM @_sql;
EXECUTE _s;
DEALLOCATE PREPARE _s;
SET @_sql = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='SDS' AND COLUMN_NAME='PARENT_ID')=1, 'ALTER TABLE `SDS` DROP COLUMN `PARENT_ID`', 'SELECT 1');
PREPARE _s FROM @_sql;
EXECUTE _s;
DEALLOCATE PREPARE _s;
SET @_sql = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='SDS' AND COLUMN_NAME='NAME')=1, 'ALTER TABLE `SDS` DROP COLUMN `NAME`', 'SELECT 1');
PREPARE _s FROM @_sql;
EXECUTE _s;
DEALLOCATE PREPARE _s;

-- The delegation token store tables, used when the metastore token store is DB-backed
-- (upstream MMasterKey/MDelegationToken). CREATE IF NOT EXISTS covers a schema that
-- genuinely lacks them; on 3.0.0.14 they are already present.
--
-- They are present but on the wrong engine. Upstream writes these two engine clauses
-- in upper case (INNODB) and its other 77 in mixed case, so the case-sensitive conversion
-- that put the Hopsworks 3.0 schema on NDB matched 71 tables and missed exactly these
-- two. An InnoDB table on a RonDB cluster lives on a single mysqld rather than in the
-- data nodes. MySqlCommandParser rewrites the engine case-insensitively, so the ALTERs
-- below both fix that and stop an upgraded cluster from diverging from a fresh install,
-- where the base 4.1 schema creates them through the same rewrite.
CREATE TABLE IF NOT EXISTS `MASTER_KEYS` (
  `KEY_ID` INTEGER NOT NULL AUTO_INCREMENT,
  `MASTER_KEY` VARCHAR(767) BINARY NULL,
  PRIMARY KEY (`KEY_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
ALTER TABLE `MASTER_KEYS` ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `DELEGATION_TOKENS` (
  `TOKEN_IDENT` VARCHAR(767) BINARY NOT NULL,
  `TOKEN` VARCHAR(767) BINARY NULL,
  PRIMARY KEY (`TOKEN_IDENT`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
ALTER TABLE `DELEGATION_TOKENS` ENGINE=InnoDB;

UPDATE VERSION SET SCHEMA_VERSION='3.0.0', VERSION_COMMENT='Hive release version 3.0.0' WHERE VER_ID=1;

SELECT 'Finished upgrading MetaStore schema from 3.0.0.14 to 3.0.0' AS MESSAGE;
