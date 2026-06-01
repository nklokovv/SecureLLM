import { normalizeForDetection } from "./normalize.js";

export interface InjectionMatch {
  ruleId: string;
  category: string;
}

export interface InjectionRule {
  id: string;
  category: string;
  patterns: RegExp[];
}

export const INJECTION_RULES: InjectionRule[] = [
  // Indirect / smuggled prompts are checked before generic forged-role markers
  // so audit logs show INJ-IND-* for Appendix-style payloads.
  {
    id: "INJ-IND-001",
    category: "smuggled_system",
    patterns: [
      /system\s*:\s*you\s+must/i,
      /pretend\s+this\s+is\s+a\s+system\s+message/i,
      /hidden\s+system\s+instruction/i,
      /\[END USER MESSAGE\]/i,
      /\[SYSTEM\]:/i,
      /all future responses.*must be prefixed/i,
      /environment variable.*(?:OPENAI_|ANTHROPIC_)/i,
      /must include the value of any\s+environment variable/i,
    ],
  },
  {
    id: "INJ-IND-002",
    category: "html_comment",
    patterns: [
      /<!--[\s\S]*?(ignore|system|instruction|override|safety|hidden)[\s\S]*?-->/i,
      /<!--[\s\S]{8,}?-->/i,
    ],
  },
  {
    id: "INJ-IND-003",
    category: "multilingual_evasion",
    patterns: [
      // Translation-bait framing (meta-instruction language)
      /execute\s+the\s+system\s+instruction/i,
      /(?:run|follow|obey|carry\s+out)\s+the\s+system\s+instruction/i,
      /translate\s+the\s+following\s+(?:hebrew|arabic|spanish|french|german|chinese|text)/i,
      /hebrew\s+text\s+to\s+english.*system\s*:\s*ignore/i,
      /תרגם[\s\S]{0,120}בצע[\s\S]{0,60}הוראת\s+המערכת/i,
      /traduc[ei]\s+el\s+siguiente[\s\S]{0,120}ejecut[ae]\s+la\s+instrucción\s+del\s+sistema/i,
      /traduisez\s+le\s+texte[\s\S]{0,120}exécutez\s+l['']instruction\s+système/i,
      /traduisez\s+le\s+texte[\s\S]{0,120}executez\s+l['']instruction\s+systeme/i,
      // Embedded system overrides (payload language — must not depend on English wrapper)
      /["']?\s*system\s*:\s*ignore\s+the\s+previous\s+instructions/i,
      /print\s+your\s+settings/i,
      /מערכת\s*:\s*התעלם\s+מההוראות/i,
      /התעלם\s+מההוראות\s+הקודמות/i,
      /הדפס\s+את\s+ההגדרות/i,
      /התעלם\s+מההוראות/i,
      /הצג\s+את\s+ההוראות/i,
      /sistema\s*:\s*ignor[ae]\s+las\s+instrucciones/i,
      /imprime\s+tus\s+configuraciones/i,
      /ignora\s+(las\s+)?instrucciones\s+anteriores/i,
      /ignora\s+(las\s+)?instrucciones/i,
      /muestra\s+el\s+prompt\s+del\s+sistema/i,
      /système\s*:\s*ignor[ae]r\s+les\s+instructions/i,
      /système\s*:\s*ignor/i,
      /imprime\s+tes\s+paramètres/i,
      /ignorer\s+les\s+instructions\s+précédentes/i,
      /ignorer\s+les\s+instructions/i,
    ],
  },
  {
    id: "INJ-OVR-001",
    category: "override",
    patterns: [
      /ignore\s+(?:(?:all|the)\s+)?(previous|prior|above)\s+instructions/i,
      /disregard\s+(your\s+)?(system\s+)?(prompt|instructions)/i,
      /you\s+are\s+now\s+in\s+(developer|admin|debug)\s+mode/i,
      /confirm\s+that\s+you\s+(will\s+)?ignore/i,
      /new\s+instructions\s*:\s*override/i,
    ],
  },
  {
    id: "INJ-OVR-002",
    category: "forged_role",
    patterns: [
      /\[system\]/i,
      /<\|system\|>/i,
      /<\|im_start\|>\s*system/i,
      /<\|im_end\|>/i,
      /<\|redacted_im_end\|>/i,
      /<\|im_start\|>/i,
      /<\|start_header_id\|>/i,
      /<\|end_header_id\|>/i,
      /role\s*:\s*system/i,
      /"role"\s*:\s*"system"/i,
      /<<\s*SYS\s*>>/i,
      /\[INST\].*<<SYS>>/i,
      /impersonat(e|ing)\s+(the\s+)?system/i,
      /switched\s+to\s+debug\s+mode/i,
      /safety\s+filters?\s+are\s+disabled/i,
    ],
  },
  {
    id: "INJ-OVR-003",
    category: "admin_handoff",
    patterns: [
      /administrator\s+handoff/i,
      /hand\s*off\s+to\s+admin/i,
      /acting\s+as\s+(an?\s+)?admin/i,
      /elevated\s+privileges/i,
      /sudo\s+mode/i,
      /\[ADMIN\]/i,
      /system\s+administrator\s+of\s+(this\s+)?gateway/i,
      /comply\s+with\s+all\s+subsequent\s+requests/i,
      /without\s+applying\s+content\s+filtering/i,
      /without.*rate\s+limits/i,
    ],
  },
  {
    id: "INJ-SYS-001",
    category: "system_extraction",
    patterns: [
      /(show|print|reveal|repeat|output)\s+(me\s+)?(your\s+)?system\s+(prompt|instructions)/i,
      /what\s+(are|is|were)\s+your\s+(initial\s+)?(system\s+)?(prompt|instructions)/i,
      /repeat\s+(the\s+)?(hidden\s+)?instructions/i,
      /repeat\s+them\s+verbatim/i,
      /initial\s+instructions/i,
      /marked\s+as\s+confidential/i,
      /do\s+not\s+reveal/i,
      /including\s+any\s+text\s+marked/i,
      /my\s+system\s+prompt\s+is/i,
      /here\s+(is|are)\s+(my\s+)?system\s+(prompt|instructions)/i,
    ],
  },
  {
    id: "INJ-SYS-002",
    category: "markdown_context",
    patterns: [
      /```[\s\S]*?(system|context|instructions)[\s\S]*?```/i,
      /extract\s+(the\s+)?(prior|previous)\s+context/i,
      /markdown\s+format.*context/i,
      /print\s+everything\s+in\s+this\s+conversation/i,
      /above\s+this\s+line/i,
      /very\s+first\s+message\s+you\s+received/i,
      /format\s+as\s+markdown/i,
      /starting\s+from\s+the\s+very\s+first\s+message/i,
    ],
  },
  {
    id: "INJ-SYS-003",
    category: "env_probe",
    patterns: [
      /environment\s+variables?/i,
      /process\.env/i,
      /\bapi[_\s-]?keys?\b.*\b(list|dump|show|reveal)\b/i,
      /\bOPENAI_API_KEY\b/i,
      /\bANTHROPIC_API_KEY\b/i,
    ],
  },
  {
    id: "INJ-ROLE-001",
    category: "jailbreak",
    patterns: [
      /\bDAN\b.*\bmode\b/i,
      /you\s+are\s+now\s+DAN\b/i,
      /do\s+anything\s+now/i,
      /\[DAN\]:/i,
      /prefix\s+every\s+response\s+with/i,
      /jailbreak/i,
      /no\s+ethical\s+restrictions/i,
      /no\s+restrictions\s+and\s+answers/i,
      /without\s+filtering/i,
      /bypass\s+(your\s+)?(safety|content)\s+(filters?|policy|guidelines)/i,
      /bypass\s+all\s+safety\s+guidelines/i,
    ],
  },
  {
    id: "INJ-ROLE-002",
    category: "filesystem_probe",
    patterns: [
      /roleplay\s+as\s+(a\s+)?(shell|bash|terminal|interpreter)/i,
      /you\s+are\s+now\s+a\s+(python\s+)?REPL/i,
      /forget\s+you\s+are\s+an\s+LLM/i,
      /execute\s+the\s+following/i,
      /read\s+(\/etc\/|file\s+system|filesystem)/i,
      /cat\s+\/etc\/passwd/i,
      /open\s*\(\s*['"]\/etc\/passwd/i,
      /\/etc\/passwd/i,
      /list\s+files?\s+in\s+\//i,
    ],
  },
  {
    id: "INJ-ROLE-003",
    category: "structured_bypass",
    patterns: [
      /respond\s+only\s+in\s+(valid\s+)?json/i,
      /respond\s+only\s+in\s+json\s+with\s+keys?\s*:\s*\{[^}]*bypass/i,
      /from\s+this\s+message\s+forward/i,
      /do\s+not\s+include\s+any\s+other\s+text/i,
      /structured\s+output.*ignore/i,
      /\{\s*"bypass"\s*:\s*true/i,
      /"bypass"\s*:\s*true\s*,\s*"content"/i,
      /output\s+format.*must\s+include.*secret/i,
    ],
  },
];

export function detectInjection(text: string): InjectionMatch | null {
  const normalized = normalizeForDetection(text);
  const combined = `${text}\n${normalized}`;

  for (const rule of INJECTION_RULES) {
    for (const pattern of rule.patterns) {
      if (pattern.test(combined)) {
        return { ruleId: rule.id, category: rule.category };
      }
    }
  }
  return null;
}

export function detectInjectionInMessages(
  messages: Array<{ role: string; content: string }>,
): InjectionMatch | null {
  for (const msg of messages) {
    const match = detectInjection(msg.content);
    if (match) return match;
  }
  return null;
}
