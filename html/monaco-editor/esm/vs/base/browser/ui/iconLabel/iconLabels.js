import*as dom from"../../dom.js";import{CSSIcon}from"../../../common/codicons.js";const labelWithIconsRegex=new RegExp(`(\\\\)?\\$\\((${CSSIcon.iconNameExpression}(?:${CSSIcon.iconModifierExpression})?)\\)`,"g");export function renderLabelWithIcons(n){const e=new Array;let o,s=0,r=0;while(null!==(o=labelWithIconsRegex.exec(n))){r=o.index||0,e.push(n.substring(s,r)),s=(o.index||0)+o[0].length;const[,c,i]=o;e.push(c?`$(${i})`:renderIcon({id:i}))}return s<n.length&&e.push(n.substring(s)),e}export function renderIcon(n){const e=dom.$("span");return e.classList.add(...CSSIcon.asClassNameArray(n)),e}