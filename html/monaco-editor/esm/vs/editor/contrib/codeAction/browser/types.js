export class CodeActionKind{constructor(e){this.value=e}equals(e){return this.value===e.value}contains(e){return this.equals(e)||""===this.value||e.value.startsWith(this.value+CodeActionKind.sep)}intersects(e){return this.contains(e)||e.contains(this)}append(e){return new CodeActionKind(this.value+CodeActionKind.sep+e)}}CodeActionKind.sep=".",CodeActionKind.None=new CodeActionKind("@@none@@"),CodeActionKind.Empty=new CodeActionKind(""),CodeActionKind.QuickFix=new CodeActionKind("quickfix"),CodeActionKind.Refactor=new CodeActionKind("refactor"),CodeActionKind.Source=new CodeActionKind("source"),CodeActionKind.SourceOrganizeImports=CodeActionKind.Source.append("organizeImports"),CodeActionKind.SourceFixAll=CodeActionKind.Source.append("fixAll");export function mayIncludeActionsOfKind(e,n){return!(e.include&&!e.include.intersects(n))&&((!e.excludes||!e.excludes.some((i=>excludesAction(n,i,e.include))))&&!(!e.includeSourceActions&&CodeActionKind.Source.contains(n)))}export function filtersAction(e,n){const i=n.kind?new CodeActionKind(n.kind):void 0;return!!(!e.include||i&&e.include.contains(i))&&(!(e.excludes&&i&&e.excludes.some((n=>excludesAction(i,n,e.include))))&&(!(!e.includeSourceActions&&i&&CodeActionKind.Source.contains(i))&&!(e.onlyIncludePreferredActions&&!n.isPreferred)))}function excludesAction(e,n,i){return!!n.contains(e)&&(!i||!n.contains(i))}export class CodeActionCommandArgs{constructor(e,n,i){this.kind=e,this.apply=n,this.preferred=i}static fromUser(e,n){return e&&"object"===typeof e?new CodeActionCommandArgs(CodeActionCommandArgs.getKindFromUser(e,n.kind),CodeActionCommandArgs.getApplyFromUser(e,n.apply),CodeActionCommandArgs.getPreferredUser(e)):new CodeActionCommandArgs(n.kind,n.apply,!1)}static getApplyFromUser(e,n){switch("string"===typeof e.apply?e.apply.toLowerCase():""){case"first":return"first";case"never":return"never";case"ifsingle":return"ifSingle";default:return n}}static getKindFromUser(e,n){return"string"===typeof e.kind?new CodeActionKind(e.kind):n}static getPreferredUser(e){return"boolean"===typeof e.preferred&&e.preferred}}