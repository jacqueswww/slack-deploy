-- Which account ansible logs in as, per host: a cloud image is root on one
-- provider and ubuntu on the next. NULL leaves the choice to ansible.
ALTER TABLE host ADD COLUMN ssh_user TEXT;
