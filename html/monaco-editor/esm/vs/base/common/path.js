import*as process from"./process.js";const CHAR_UPPERCASE_A=65,CHAR_LOWERCASE_A=97,CHAR_UPPERCASE_Z=90,CHAR_LOWERCASE_Z=122,CHAR_DOT=46,CHAR_FORWARD_SLASH=47,CHAR_BACKWARD_SLASH=92,CHAR_COLON=58,CHAR_QUESTION_MARK=63;class ErrorInvalidArgType extends Error{constructor(e,t,r){let i;"string"===typeof t&&0===t.indexOf("not ")?(i="must not be",t=t.replace(/^not /,"")):i="must be";const a=-1!==e.indexOf(".")?"property":"argument";let o=`The "${e}" ${a} ${i} of type ${t}`;o+=". Received type "+typeof r,super(o),this.code="ERR_INVALID_ARG_TYPE"}}function validateString(e,t){if("string"!==typeof e)throw new ErrorInvalidArgType(t,"string",e)}function isPathSeparator(e){return e===CHAR_FORWARD_SLASH||e===CHAR_BACKWARD_SLASH}function isPosixPathSeparator(e){return e===CHAR_FORWARD_SLASH}function isWindowsDeviceRoot(e){return e>=CHAR_UPPERCASE_A&&e<=CHAR_UPPERCASE_Z||e>=CHAR_LOWERCASE_A&&e<=CHAR_LOWERCASE_Z}function normalizeString(e,t,r,i){let a="",o=0,n=-1,l=0,s=0;for(let A=0;A<=e.length;++A){if(A<e.length)s=e.charCodeAt(A);else{if(i(s))break;s=CHAR_FORWARD_SLASH}if(i(s)){if(n===A-1||1===l);else if(2===l){if(a.length<2||2!==o||a.charCodeAt(a.length-1)!==CHAR_DOT||a.charCodeAt(a.length-2)!==CHAR_DOT){if(a.length>2){const e=a.lastIndexOf(r);-1===e?(a="",o=0):(a=a.slice(0,e),o=a.length-1-a.lastIndexOf(r)),n=A,l=0;continue}if(0!==a.length){a="",o=0,n=A,l=0;continue}}t&&(a+=a.length>0?`${r}..`:"..",o=2)}else a.length>0?a+=`${r}${e.slice(n+1,A)}`:a=e.slice(n+1,A),o=A-n-1;n=A,l=0}else s===CHAR_DOT&&-1!==l?++l:l=-1}return a}function _format(e,t){if(null===t||"object"!==typeof t)throw new ErrorInvalidArgType("pathObject","Object",t);const r=t.dir||t.root,i=t.base||`${t.name||""}${t.ext||""}`;return r?r===t.root?`${r}${i}`:`${r}${e}${i}`:i}export const win32={resolve(...e){let t="",r="",i=!1;for(let a=e.length-1;a>=-1;a--){let o;if(a>=0){if(o=e[a],validateString(o,"path"),0===o.length)continue}else 0===t.length?o=process.cwd():(o=process.env[`=${t}`]||process.cwd(),(void 0===o||o.slice(0,2).toLowerCase()!==t.toLowerCase()&&o.charCodeAt(2)===CHAR_BACKWARD_SLASH)&&(o=`${t}\\`));const n=o.length;let l=0,s="",A=!1;const h=o.charCodeAt(0);if(1===n)isPathSeparator(h)&&(l=1,A=!0);else if(isPathSeparator(h))if(A=!0,isPathSeparator(o.charCodeAt(1))){let e=2,t=e;while(e<n&&!isPathSeparator(o.charCodeAt(e)))e++;if(e<n&&e!==t){const r=o.slice(t,e);t=e;while(e<n&&isPathSeparator(o.charCodeAt(e)))e++;if(e<n&&e!==t){t=e;while(e<n&&!isPathSeparator(o.charCodeAt(e)))e++;e!==n&&e===t||(s=`\\\\${r}\\${o.slice(t,e)}`,l=e)}}}else l=1;else isWindowsDeviceRoot(h)&&o.charCodeAt(1)===CHAR_COLON&&(s=o.slice(0,2),l=2,n>2&&isPathSeparator(o.charCodeAt(2))&&(A=!0,l=3));if(s.length>0)if(t.length>0){if(s.toLowerCase()!==t.toLowerCase())continue}else t=s;if(i){if(t.length>0)break}else if(r=`${o.slice(l)}\\${r}`,i=A,A&&t.length>0)break}return r=normalizeString(r,!i,"\\",isPathSeparator),i?`${t}\\${r}`:`${t}${r}`||"."},normalize(e){validateString(e,"path");const t=e.length;if(0===t)return".";let r,i=0,a=!1;const o=e.charCodeAt(0);if(1===t)return isPosixPathSeparator(o)?"\\":e;if(isPathSeparator(o))if(a=!0,isPathSeparator(e.charCodeAt(1))){let a=2,o=a;while(a<t&&!isPathSeparator(e.charCodeAt(a)))a++;if(a<t&&a!==o){const n=e.slice(o,a);o=a;while(a<t&&isPathSeparator(e.charCodeAt(a)))a++;if(a<t&&a!==o){o=a;while(a<t&&!isPathSeparator(e.charCodeAt(a)))a++;if(a===t)return`\\\\${n}\\${e.slice(o)}\\`;a!==o&&(r=`\\\\${n}\\${e.slice(o,a)}`,i=a)}}}else i=1;else isWindowsDeviceRoot(o)&&e.charCodeAt(1)===CHAR_COLON&&(r=e.slice(0,2),i=2,t>2&&isPathSeparator(e.charCodeAt(2))&&(a=!0,i=3));let n=i<t?normalizeString(e.slice(i),!a,"\\",isPathSeparator):"";return 0!==n.length||a||(n="."),n.length>0&&isPathSeparator(e.charCodeAt(t-1))&&(n+="\\"),void 0===r?a?`\\${n}`:n:a?`${r}\\${n}`:`${r}${n}`},isAbsolute(e){validateString(e,"path");const t=e.length;if(0===t)return!1;const r=e.charCodeAt(0);return isPathSeparator(r)||t>2&&isWindowsDeviceRoot(r)&&e.charCodeAt(1)===CHAR_COLON&&isPathSeparator(e.charCodeAt(2))},join(...e){if(0===e.length)return".";let t,r;for(let o=0;o<e.length;++o){const i=e[o];validateString(i,"path"),i.length>0&&(void 0===t?t=r=i:t+=`\\${i}`)}if(void 0===t)return".";let i=!0,a=0;if("string"===typeof r&&isPathSeparator(r.charCodeAt(0))){++a;const e=r.length;e>1&&isPathSeparator(r.charCodeAt(1))&&(++a,e>2&&(isPathSeparator(r.charCodeAt(2))?++a:i=!1))}if(i){while(a<t.length&&isPathSeparator(t.charCodeAt(a)))a++;a>=2&&(t=`\\${t.slice(a)}`)}return win32.normalize(t)},relative(e,t){if(validateString(e,"from"),validateString(t,"to"),e===t)return"";const r=win32.resolve(e),i=win32.resolve(t);if(r===i)return"";if(e=r.toLowerCase(),t=i.toLowerCase(),e===t)return"";let a=0;while(a<e.length&&e.charCodeAt(a)===CHAR_BACKWARD_SLASH)a++;let o=e.length;while(o-1>a&&e.charCodeAt(o-1)===CHAR_BACKWARD_SLASH)o--;const n=o-a;let l=0;while(l<t.length&&t.charCodeAt(l)===CHAR_BACKWARD_SLASH)l++;let s=t.length;while(s-1>l&&t.charCodeAt(s-1)===CHAR_BACKWARD_SLASH)s--;const A=s-l,h=n<A?n:A;let c=-1,C=0;for(;C<h;C++){const r=e.charCodeAt(a+C);if(r!==t.charCodeAt(l+C))break;r===CHAR_BACKWARD_SLASH&&(c=C)}if(C!==h){if(-1===c)return i}else{if(A>h){if(t.charCodeAt(l+C)===CHAR_BACKWARD_SLASH)return i.slice(l+C+1);if(2===C)return i.slice(l+C)}n>h&&(e.charCodeAt(a+C)===CHAR_BACKWARD_SLASH?c=C:2===C&&(c=3)),-1===c&&(c=0)}let d="";for(C=a+c+1;C<=o;++C)C!==o&&e.charCodeAt(C)!==CHAR_BACKWARD_SLASH||(d+=0===d.length?"..":"\\..");return l+=c,d.length>0?`${d}${i.slice(l,s)}`:(i.charCodeAt(l)===CHAR_BACKWARD_SLASH&&++l,i.slice(l,s))},toNamespacedPath(e){if("string"!==typeof e)return e;if(0===e.length)return"";const t=win32.resolve(e);if(t.length<=2)return e;if(t.charCodeAt(0)===CHAR_BACKWARD_SLASH){if(t.charCodeAt(1)===CHAR_BACKWARD_SLASH){const e=t.charCodeAt(2);if(e!==CHAR_QUESTION_MARK&&e!==CHAR_DOT)return`\\\\?\\UNC\\${t.slice(2)}`}}else if(isWindowsDeviceRoot(t.charCodeAt(0))&&t.charCodeAt(1)===CHAR_COLON&&t.charCodeAt(2)===CHAR_BACKWARD_SLASH)return`\\\\?\\${t}`;return e},dirname(e){validateString(e,"path");const t=e.length;if(0===t)return".";let r=-1,i=0;const a=e.charCodeAt(0);if(1===t)return isPathSeparator(a)?e:".";if(isPathSeparator(a)){if(r=i=1,isPathSeparator(e.charCodeAt(1))){let a=2,o=a;while(a<t&&!isPathSeparator(e.charCodeAt(a)))a++;if(a<t&&a!==o){o=a;while(a<t&&isPathSeparator(e.charCodeAt(a)))a++;if(a<t&&a!==o){o=a;while(a<t&&!isPathSeparator(e.charCodeAt(a)))a++;if(a===t)return e;a!==o&&(r=i=a+1)}}}}else isWindowsDeviceRoot(a)&&e.charCodeAt(1)===CHAR_COLON&&(r=t>2&&isPathSeparator(e.charCodeAt(2))?3:2,i=r);let o=-1,n=!0;for(let l=t-1;l>=i;--l)if(isPathSeparator(e.charCodeAt(l))){if(!n){o=l;break}}else n=!1;if(-1===o){if(-1===r)return".";o=r}return e.slice(0,o)},basename(e,t){void 0!==t&&validateString(t,"ext"),validateString(e,"path");let r,i=0,a=-1,o=!0;if(e.length>=2&&isWindowsDeviceRoot(e.charCodeAt(0))&&e.charCodeAt(1)===CHAR_COLON&&(i=2),void 0!==t&&t.length>0&&t.length<=e.length){if(t===e)return"";let n=t.length-1,l=-1;for(r=e.length-1;r>=i;--r){const s=e.charCodeAt(r);if(isPathSeparator(s)){if(!o){i=r+1;break}}else-1===l&&(o=!1,l=r+1),n>=0&&(s===t.charCodeAt(n)?-1===--n&&(a=r):(n=-1,a=l))}return i===a?a=l:-1===a&&(a=e.length),e.slice(i,a)}for(r=e.length-1;r>=i;--r)if(isPathSeparator(e.charCodeAt(r))){if(!o){i=r+1;break}}else-1===a&&(o=!1,a=r+1);return-1===a?"":e.slice(i,a)},extname(e){validateString(e,"path");let t=0,r=-1,i=0,a=-1,o=!0,n=0;e.length>=2&&e.charCodeAt(1)===CHAR_COLON&&isWindowsDeviceRoot(e.charCodeAt(0))&&(t=i=2);for(let l=e.length-1;l>=t;--l){const t=e.charCodeAt(l);if(isPathSeparator(t)){if(!o){i=l+1;break}}else-1===a&&(o=!1,a=l+1),t===CHAR_DOT?-1===r?r=l:1!==n&&(n=1):-1!==r&&(n=-1)}return-1===r||-1===a||0===n||1===n&&r===a-1&&r===i+1?"":e.slice(r,a)},format:_format.bind(null,"\\"),parse(e){validateString(e,"path");const t={root:"",dir:"",base:"",ext:"",name:""};if(0===e.length)return t;const r=e.length;let i=0,a=e.charCodeAt(0);if(1===r)return isPathSeparator(a)?(t.root=t.dir=e,t):(t.base=t.name=e,t);if(isPathSeparator(a)){if(i=1,isPathSeparator(e.charCodeAt(1))){let t=2,a=t;while(t<r&&!isPathSeparator(e.charCodeAt(t)))t++;if(t<r&&t!==a){a=t;while(t<r&&isPathSeparator(e.charCodeAt(t)))t++;if(t<r&&t!==a){a=t;while(t<r&&!isPathSeparator(e.charCodeAt(t)))t++;t===r?i=t:t!==a&&(i=t+1)}}}}else if(isWindowsDeviceRoot(a)&&e.charCodeAt(1)===CHAR_COLON){if(r<=2)return t.root=t.dir=e,t;if(i=2,isPathSeparator(e.charCodeAt(2))){if(3===r)return t.root=t.dir=e,t;i=3}}i>0&&(t.root=e.slice(0,i));let o=-1,n=i,l=-1,s=!0,A=e.length-1,h=0;for(;A>=i;--A)if(a=e.charCodeAt(A),isPathSeparator(a)){if(!s){n=A+1;break}}else-1===l&&(s=!1,l=A+1),a===CHAR_DOT?-1===o?o=A:1!==h&&(h=1):-1!==o&&(h=-1);return-1!==l&&(-1===o||0===h||1===h&&o===l-1&&o===n+1?t.base=t.name=e.slice(n,l):(t.name=e.slice(n,o),t.base=e.slice(n,l),t.ext=e.slice(o,l))),t.dir=n>0&&n!==i?e.slice(0,n-1):t.root,t},sep:"\\",delimiter:";",win32:null,posix:null};export const posix={resolve(...e){let t="",r=!1;for(let i=e.length-1;i>=-1&&!r;i--){const a=i>=0?e[i]:process.cwd();validateString(a,"path"),0!==a.length&&(t=`${a}/${t}`,r=a.charCodeAt(0)===CHAR_FORWARD_SLASH)}return t=normalizeString(t,!r,"/",isPosixPathSeparator),r?`/${t}`:t.length>0?t:"."},normalize(e){if(validateString(e,"path"),0===e.length)return".";const t=e.charCodeAt(0)===CHAR_FORWARD_SLASH,r=e.charCodeAt(e.length-1)===CHAR_FORWARD_SLASH;return e=normalizeString(e,!t,"/",isPosixPathSeparator),0===e.length?t?"/":r?"./":".":(r&&(e+="/"),t?`/${e}`:e)},isAbsolute(e){return validateString(e,"path"),e.length>0&&e.charCodeAt(0)===CHAR_FORWARD_SLASH},join(...e){if(0===e.length)return".";let t;for(let r=0;r<e.length;++r){const i=e[r];validateString(i,"path"),i.length>0&&(void 0===t?t=i:t+=`/${i}`)}return void 0===t?".":posix.normalize(t)},relative(e,t){if(validateString(e,"from"),validateString(t,"to"),e===t)return"";if(e=posix.resolve(e),t=posix.resolve(t),e===t)return"";const r=1,i=e.length,a=i-r,o=1,n=t.length-o,l=a<n?a:n;let s=-1,A=0;for(;A<l;A++){const i=e.charCodeAt(r+A);if(i!==t.charCodeAt(o+A))break;i===CHAR_FORWARD_SLASH&&(s=A)}if(A===l)if(n>l){if(t.charCodeAt(o+A)===CHAR_FORWARD_SLASH)return t.slice(o+A+1);if(0===A)return t.slice(o+A)}else a>l&&(e.charCodeAt(r+A)===CHAR_FORWARD_SLASH?s=A:0===A&&(s=0));let h="";for(A=r+s+1;A<=i;++A)A!==i&&e.charCodeAt(A)!==CHAR_FORWARD_SLASH||(h+=0===h.length?"..":"/..");return`${h}${t.slice(o+s)}`},toNamespacedPath(e){return e},dirname(e){if(validateString(e,"path"),0===e.length)return".";const t=e.charCodeAt(0)===CHAR_FORWARD_SLASH;let r=-1,i=!0;for(let a=e.length-1;a>=1;--a)if(e.charCodeAt(a)===CHAR_FORWARD_SLASH){if(!i){r=a;break}}else i=!1;return-1===r?t?"/":".":t&&1===r?"//":e.slice(0,r)},basename(e,t){void 0!==t&&validateString(t,"ext"),validateString(e,"path");let r,i=0,a=-1,o=!0;if(void 0!==t&&t.length>0&&t.length<=e.length){if(t===e)return"";let n=t.length-1,l=-1;for(r=e.length-1;r>=0;--r){const s=e.charCodeAt(r);if(s===CHAR_FORWARD_SLASH){if(!o){i=r+1;break}}else-1===l&&(o=!1,l=r+1),n>=0&&(s===t.charCodeAt(n)?-1===--n&&(a=r):(n=-1,a=l))}return i===a?a=l:-1===a&&(a=e.length),e.slice(i,a)}for(r=e.length-1;r>=0;--r)if(e.charCodeAt(r)===CHAR_FORWARD_SLASH){if(!o){i=r+1;break}}else-1===a&&(o=!1,a=r+1);return-1===a?"":e.slice(i,a)},extname(e){validateString(e,"path");let t=-1,r=0,i=-1,a=!0,o=0;for(let n=e.length-1;n>=0;--n){const l=e.charCodeAt(n);if(l!==CHAR_FORWARD_SLASH)-1===i&&(a=!1,i=n+1),l===CHAR_DOT?-1===t?t=n:1!==o&&(o=1):-1!==t&&(o=-1);else if(!a){r=n+1;break}}return-1===t||-1===i||0===o||1===o&&t===i-1&&t===r+1?"":e.slice(t,i)},format:_format.bind(null,"/"),parse(e){validateString(e,"path");const t={root:"",dir:"",base:"",ext:"",name:""};if(0===e.length)return t;const r=e.charCodeAt(0)===CHAR_FORWARD_SLASH;let i;r?(t.root="/",i=1):i=0;let a=-1,o=0,n=-1,l=!0,s=e.length-1,A=0;for(;s>=i;--s){const t=e.charCodeAt(s);if(t!==CHAR_FORWARD_SLASH)-1===n&&(l=!1,n=s+1),t===CHAR_DOT?-1===a?a=s:1!==A&&(A=1):-1!==a&&(A=-1);else if(!l){o=s+1;break}}if(-1!==n){const i=0===o&&r?1:o;-1===a||0===A||1===A&&a===n-1&&a===o+1?t.base=t.name=e.slice(i,n):(t.name=e.slice(i,a),t.base=e.slice(i,n),t.ext=e.slice(a,n))}return o>0?t.dir=e.slice(0,o-1):r&&(t.dir="/"),t},sep:"/",delimiter:":",win32:null,posix:null};posix.win32=win32.win32=win32,posix.posix=win32.posix=posix;export const normalize="win32"===process.platform?win32.normalize:posix.normalize;export const resolve="win32"===process.platform?win32.resolve:posix.resolve;export const relative="win32"===process.platform?win32.relative:posix.relative;export const dirname="win32"===process.platform?win32.dirname:posix.dirname;export const basename="win32"===process.platform?win32.basename:posix.basename;export const extname="win32"===process.platform?win32.extname:posix.extname;export const sep="win32"===process.platform?win32.sep:posix.sep;