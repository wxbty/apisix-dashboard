import{IdleValue}from"./async.js";const intlFileNameCollatorBaseNumeric=new IdleValue((()=>{const e=new Intl.Collator(void 0,{numeric:!0,sensitivity:"base"});return{collator:e,collatorIsNumeric:e.resolvedOptions().numeric}})),intlFileNameCollatorNumeric=new IdleValue((()=>{const e=new Intl.Collator(void 0,{numeric:!0});return{collator:e}})),intlFileNameCollatorNumericCaseInsensitive=new IdleValue((()=>{const e=new Intl.Collator(void 0,{numeric:!0,sensitivity:"accent"});return{collator:e}}));export function compareFileNames(e,t,r=!1){const o=e||"",l=t||"",n=intlFileNameCollatorBaseNumeric.value.collator.compare(o,l);return intlFileNameCollatorBaseNumeric.value.collatorIsNumeric&&0===n&&o!==l?o<l?-1:1:n}export function compareAnything(e,t,r){const o=e.toLowerCase(),l=t.toLowerCase(),n=compareByPrefix(e,t,r);if(n)return n;const i=o.endsWith(r),a=l.endsWith(r);if(i!==a)return i?-1:1;const c=compareFileNames(o,l);return 0!==c?c:o.localeCompare(l)}export function compareByPrefix(e,t,r){const o=e.toLowerCase(),l=t.toLowerCase(),n=o.startsWith(r),i=l.startsWith(r);if(n!==i)return n?-1:1;if(n&&i){if(o.length<l.length)return-1;if(o.length>l.length)return 1}return 0}