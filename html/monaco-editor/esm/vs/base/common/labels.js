import{hasDriveLetter,isRootOrDriveLetter}from"./extpath.js";import{Schemas}from"./network.js";import{isWindows}from"./platform.js";import{basename}from"./resources.js";import{URI}from"./uri.js";export function getBaseLabel(e){if(!e)return;"string"===typeof e&&(e=URI.file(e));const r=basename(e)||(e.scheme===Schemas.file?e.fsPath:e.path);return isWindows&&isRootOrDriveLetter(r)?normalizeDriveLetter(r):r}export function normalizeDriveLetter(e,r){return hasDriveLetter(e,r)?e.charAt(0).toUpperCase()+e.slice(1):e}let normalizedUserHomeCached=Object.create(null);