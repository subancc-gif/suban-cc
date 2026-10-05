// Supabase connection for AutoBOQ (the HR project; AutoBOQ data lives in its own "autoboq" schema).
// Both values are safe to publish: the publishable key only works together with the
// row-level security rules in supabase/schema.sql (HR employees only, by role).
// Find them in Supabase Dashboard → Project Settings → API.
window.AUTOBOQ_CONFIG = {
  supabaseUrl: "https://qnvlaehhfrgmosulfcdg.supabase.co",
  supabaseAnonKey: "sb_publishable_v2KYE5ZKnSt7EwimTZjC2w_ub89OTg9",
  emailDomain: "subancc.local" // must match emailDomain in the HR app's config.js
};
