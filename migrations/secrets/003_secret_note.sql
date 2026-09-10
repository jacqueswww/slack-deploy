-- Optional free-text note per variable: what it is for, where it came from, who
-- to ask. Lives in the encrypted database because the note itself often hints at
-- what the value is.
ALTER TABLE secret ADD COLUMN note TEXT;
