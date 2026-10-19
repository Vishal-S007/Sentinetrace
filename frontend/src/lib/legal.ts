/** The public legal pages, in display order. */
export const LEGAL_DOCS = [
  { slug: 'privacy', title: 'Privacy policy' },
  { slug: 'terms', title: 'Terms of service' },
  { slug: 'cookies', title: 'Cookie policy' },
] as const

export type LegalSlug = (typeof LEGAL_DOCS)[number]['slug']
