import{isArray,isObject,isUndefinedOrNull}from"./types.js";export function deepClone(e){if(!e||"object"!==typeof e)return e;if(e instanceof RegExp)return e;const r=Array.isArray(e)?[]:{};return Object.keys(e).forEach((t=>{e[t]&&"object"===typeof e[t]?r[t]=deepClone(e[t]):r[t]=e[t]})),r}export function deepFreeze(e){if(!e||"object"!==typeof e)return e;const r=[e];while(r.length>0){const e=r.shift();Object.freeze(e);for(const t in e)if(_hasOwnProperty.call(e,t)){const n=e[t];"object"!==typeof n||Object.isFrozen(n)||r.push(n)}}return e}const _hasOwnProperty=Object.prototype.hasOwnProperty;export function cloneAndChange(e,r){return _cloneAndChange(e,r,new Set)}function _cloneAndChange(e,r,t){if(isUndefinedOrNull(e))return e;const n=r(e);if("undefined"!==typeof n)return n;if(isArray(e)){const n=[];for(const o of e)n.push(_cloneAndChange(o,r,t));return n}if(isObject(e)){if(t.has(e))throw new Error("Cannot clone recursive data-structure");t.add(e);const n={};for(let o in e)_hasOwnProperty.call(e,o)&&(n[o]=_cloneAndChange(e[o],r,t));return t.delete(e),n}return e}export function mixin(e,r,t=!0){return isObject(e)?(isObject(r)&&Object.keys(r).forEach((n=>{n in e?t&&(isObject(e[n])&&isObject(r[n])?mixin(e[n],r[n],t):e[n]=r[n]):e[n]=r[n]})),e):r}export function equals(e,r){if(e===r)return!0;if(null===e||void 0===e||null===r||void 0===r)return!1;if(typeof e!==typeof r)return!1;if("object"!==typeof e)return!1;if(Array.isArray(e)!==Array.isArray(r))return!1;let t,n;if(Array.isArray(e)){if(e.length!==r.length)return!1;for(t=0;t<e.length;t++)if(!equals(e[t],r[t]))return!1}else{const o=[];for(n in e)o.push(n);o.sort();const i=[];for(n in r)i.push(n);if(i.sort(),!equals(o,i))return!1;for(t=0;t<o.length;t++)if(!equals(e[o[t]],r[o[t]]))return!1}return!0}export function getOrDefault(e,r,t){const n=r(e);return"undefined"===typeof n?t:n}