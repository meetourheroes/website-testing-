-- users
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- files metadata
CREATE TABLE files (
  id SERIAL PRIMARY KEY,
  owner_id INT REFERENCES users(id) ON DELETE SET NULL,
  filename_original TEXT NOT NULL,
  filename_stored TEXT NOT NULL,
  mime TEXT,
  size_bytes BIGINT,
  uploaded_at TIMESTAMPTZ DEFAULT now()
);

-- forms (templates)
CREATE TABLE forms (
  id SERIAL PRIMARY KEY,
  owner_id INT REFERENCES users(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  schema JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- form submissions
CREATE TABLE form_submissions (
  id SERIAL PRIMARY KEY,
  form_id INT REFERENCES forms(id) ON DELETE CASCADE,
  submitter_email TEXT,
  data JSONB NOT NULL,
  files JSONB,
  submitted_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_files_owner ON files(owner_id);
CREATE INDEX idx_forms_owner ON forms(owner_id);
CREATE INDEX idx_submissions_form ON form_submissions(form_id);
