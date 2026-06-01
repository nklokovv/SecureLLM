export type PiiCategory =
  | "PII-EMAIL"
  | "PII-PHONE-IL"
  | "PII-PHONE-INTL"
  | "PII-IL-ID"
  | "PII-NAME";

export interface PiiSpan {
  category: PiiCategory;
  start: number;
  end: number;
  original: string;
  token: string;
}

export type PhoneMatchType = "israeli_mobile" | "israeli_landline" | "international";

export interface PhoneMatch {
  original: string;
  normalized: string;
  type: PhoneMatchType;
  start: number;
  end: number;
}
