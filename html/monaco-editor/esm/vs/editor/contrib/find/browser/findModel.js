import{findFirstInSorted}from"../../../../base/common/arrays.js";import{RunOnceScheduler,TimeoutTimer}from"../../../../base/common/async.js";import{DisposableStore,dispose}from"../../../../base/common/lifecycle.js";import{ReplaceCommand,ReplaceCommandThatPreservesSelection}from"../../../common/commands/replaceCommand.js";import{Position}from"../../../common/core/position.js";import{Range}from"../../../common/core/range.js";import{Selection}from"../../../common/core/selection.js";import{SearchParams}from"../../../common/model/textModelSearch.js";import{FindDecorations}from"./findDecorations.js";import{ReplaceAllCommand}from"./replaceAllCommand.js";import{parseReplaceString,ReplacePattern}from"./replacePattern.js";import{RawContextKey}from"../../../../platform/contextkey/common/contextkey.js";export const CONTEXT_FIND_WIDGET_VISIBLE=new RawContextKey("findWidgetVisible",!1);export const CONTEXT_FIND_WIDGET_NOT_VISIBLE=CONTEXT_FIND_WIDGET_VISIBLE.toNegated();export const CONTEXT_FIND_INPUT_FOCUSED=new RawContextKey("findInputFocussed",!1);export const CONTEXT_REPLACE_INPUT_FOCUSED=new RawContextKey("replaceInputFocussed",!1);export const ToggleCaseSensitiveKeybinding={primary:545,mac:{primary:2593}};export const ToggleWholeWordKeybinding={primary:565,mac:{primary:2613}};export const ToggleRegexKeybinding={primary:560,mac:{primary:2608}};export const ToggleSearchScopeKeybinding={primary:554,mac:{primary:2602}};export const TogglePreserveCaseKeybinding={primary:558,mac:{primary:2606}};export const FIND_IDS={StartFindAction:"actions.find",StartFindWithSelection:"actions.findWithSelection",StartFindWithArgs:"editor.actions.findWithArgs",NextMatchFindAction:"editor.action.nextMatchFindAction",PreviousMatchFindAction:"editor.action.previousMatchFindAction",NextSelectionMatchFindAction:"editor.action.nextSelectionMatchFindAction",PreviousSelectionMatchFindAction:"editor.action.previousSelectionMatchFindAction",StartFindReplaceAction:"editor.action.startFindReplaceAction",CloseFindWidgetCommand:"closeFindWidget",ToggleCaseSensitiveCommand:"toggleFindCaseSensitive",ToggleWholeWordCommand:"toggleFindWholeWord",ToggleRegexCommand:"toggleFindRegex",ToggleSearchScopeCommand:"toggleFindInSelection",TogglePreserveCaseCommand:"togglePreserveCase",ReplaceOneAction:"editor.action.replaceOne",ReplaceAllAction:"editor.action.replaceAll",SelectAllMatchesAction:"editor.action.selectAllMatches"};export const MATCHES_LIMIT=19999;const RESEARCH_DELAY=240;export class FindModelBoundToEditorModel{constructor(e,t){this._toDispose=new DisposableStore,this._editor=e,this._state=t,this._isDisposed=!1,this._startSearchingTimer=new TimeoutTimer,this._decorations=new FindDecorations(e),this._toDispose.add(this._decorations),this._updateDecorationsScheduler=new RunOnceScheduler((()=>this.research(!1)),100),this._toDispose.add(this._updateDecorationsScheduler),this._toDispose.add(this._editor.onDidChangeCursorPosition((e=>{3!==e.reason&&5!==e.reason&&6!==e.reason||this._decorations.setStartPosition(this._editor.getPosition())}))),this._ignoreModelContentChanged=!1,this._toDispose.add(this._editor.onDidChangeModelContent((e=>{this._ignoreModelContentChanged||(e.isFlush&&this._decorations.reset(),this._decorations.setStartPosition(this._editor.getPosition()),this._updateDecorationsScheduler.schedule())}))),this._toDispose.add(this._state.onFindReplaceStateChange((e=>this._onStateChanged(e)))),this.research(!1,this._state.searchScope)}dispose(){this._isDisposed=!0,dispose(this._startSearchingTimer),this._toDispose.dispose()}_onStateChanged(e){if(!this._isDisposed&&this._editor.hasModel()&&(e.searchString||e.isReplaceRevealed||e.isRegex||e.wholeWord||e.matchCase||e.searchScope)){let t=this._editor.getModel();t.isTooLargeForSyncing()?(this._startSearchingTimer.cancel(),this._startSearchingTimer.setIfNotSet((()=>{e.searchScope?this.research(e.moveCursor,this._state.searchScope):this.research(e.moveCursor)}),RESEARCH_DELAY)):e.searchScope?this.research(e.moveCursor,this._state.searchScope):this.research(e.moveCursor)}}static _getSearchRange(e,t){return t||e.getFullModelRange()}research(e,t){let i=null;"undefined"!==typeof t?null!==t&&(i=Array.isArray(t)?t:[t]):i=this._decorations.getFindScopes(),null!==i&&(i=i.map((e=>{if(e.startLineNumber!==e.endLineNumber){let t=e.endLineNumber;return 1===e.endColumn&&(t-=1),new Range(e.startLineNumber,1,t,this._editor.getModel().getLineMaxColumn(t))}return e})));let o=this._findMatches(i,!1,MATCHES_LIMIT);this._decorations.set(o,i);const s=this._editor.getSelection();let n=this._decorations.getCurrentMatchesPosition(s);if(0===n&&o.length>0){const e=findFirstInSorted(o.map((e=>e.range)),(e=>Range.compareRangesUsingStarts(e,s)>=0));n=e>0?e-1+1:n}this._state.changeMatchInfo(n,this._decorations.getCount(),void 0),e&&this._editor.getOption(35).cursorMoveOnType&&this._moveToNextMatch(this._decorations.getStartPosition())}_hasMatches(){return this._state.matchesCount>0}_cannotFind(){if(!this._hasMatches()){let e=this._decorations.getFindScope();return e&&this._editor.revealRangeInCenterIfOutsideViewport(e,0),!0}return!1}_setCurrentFindMatch(e){let t=this._decorations.setCurrentFindMatch(e);this._state.changeMatchInfo(t,this._decorations.getCount(),e),this._editor.setSelection(e),this._editor.revealRangeInCenterIfOutsideViewport(e,0)}_prevSearchPosition(e){let t=this._state.isRegex&&(this._state.searchString.indexOf("^")>=0||this._state.searchString.indexOf("$")>=0),{lineNumber:i,column:o}=e,s=this._editor.getModel();return t||1===o?(1===i?i=s.getLineCount():i--,o=s.getLineMaxColumn(i)):o--,new Position(i,o)}_moveToPrevMatch(e,t=!1){if(!this._state.canNavigateBack()){const t=this._decorations.matchAfterPosition(e);return void(t&&this._setCurrentFindMatch(t))}if(this._decorations.getCount()<MATCHES_LIMIT){let t=this._decorations.matchBeforePosition(e);return t&&t.isEmpty()&&t.getStartPosition().equals(e)&&(e=this._prevSearchPosition(e),t=this._decorations.matchBeforePosition(e)),void(t&&this._setCurrentFindMatch(t))}if(this._cannotFind())return;let i=this._decorations.getFindScope(),o=FindModelBoundToEditorModel._getSearchRange(this._editor.getModel(),i);o.getEndPosition().isBefore(e)&&(e=o.getEndPosition()),e.isBefore(o.getStartPosition())&&(e=o.getEndPosition());let{lineNumber:s,column:n}=e,r=this._editor.getModel(),a=new Position(s,n),c=r.findPreviousMatch(this._state.searchString,a,this._state.isRegex,this._state.matchCase,this._state.wholeWord?this._editor.getOption(117):null,!1);return c&&c.range.isEmpty()&&c.range.getStartPosition().equals(a)&&(a=this._prevSearchPosition(a),c=r.findPreviousMatch(this._state.searchString,a,this._state.isRegex,this._state.matchCase,this._state.wholeWord?this._editor.getOption(117):null,!1)),c?t||o.containsRange(c.range)?void this._setCurrentFindMatch(c.range):this._moveToPrevMatch(c.range.getStartPosition(),!0):void 0}moveToPrevMatch(){this._moveToPrevMatch(this._editor.getSelection().getStartPosition())}_nextSearchPosition(e){let t=this._state.isRegex&&(this._state.searchString.indexOf("^")>=0||this._state.searchString.indexOf("$")>=0),{lineNumber:i,column:o}=e,s=this._editor.getModel();return t||o===s.getLineMaxColumn(i)?(i===s.getLineCount()?i=1:i++,o=1):o++,new Position(i,o)}_moveToNextMatch(e){if(!this._state.canNavigateForward()){const t=this._decorations.matchBeforePosition(e);return void(t&&this._setCurrentFindMatch(t))}if(this._decorations.getCount()<MATCHES_LIMIT){let t=this._decorations.matchAfterPosition(e);return t&&t.isEmpty()&&t.getStartPosition().equals(e)&&(e=this._nextSearchPosition(e),t=this._decorations.matchAfterPosition(e)),void(t&&this._setCurrentFindMatch(t))}let t=this._getNextMatch(e,!1,!0);t&&this._setCurrentFindMatch(t.range)}_getNextMatch(e,t,i,o=!1){if(this._cannotFind())return null;let s=this._decorations.getFindScope(),n=FindModelBoundToEditorModel._getSearchRange(this._editor.getModel(),s);n.getEndPosition().isBefore(e)&&(e=n.getStartPosition()),e.isBefore(n.getStartPosition())&&(e=n.getStartPosition());let{lineNumber:r,column:a}=e,c=this._editor.getModel(),h=new Position(r,a),d=c.findNextMatch(this._state.searchString,h,this._state.isRegex,this._state.matchCase,this._state.wholeWord?this._editor.getOption(117):null,t);return i&&d&&d.range.isEmpty()&&d.range.getStartPosition().equals(h)&&(h=this._nextSearchPosition(h),d=c.findNextMatch(this._state.searchString,h,this._state.isRegex,this._state.matchCase,this._state.wholeWord?this._editor.getOption(117):null,t)),d?o||n.containsRange(d.range)?d:this._getNextMatch(d.range.getEndPosition(),t,i,!0):null}moveToNextMatch(){this._moveToNextMatch(this._editor.getSelection().getEndPosition())}_getReplacePattern(){return this._state.isRegex?parseReplaceString(this._state.replaceString):ReplacePattern.fromStaticValue(this._state.replaceString)}replace(){if(!this._hasMatches())return;let e=this._getReplacePattern(),t=this._editor.getSelection(),i=this._getNextMatch(t.getStartPosition(),!0,!1);if(i)if(t.equalsRange(i.range)){let o=e.buildReplaceString(i.matches,this._state.preserveCase),s=new ReplaceCommand(t,o);this._executeEditorCommand("replace",s),this._decorations.setStartPosition(new Position(t.startLineNumber,t.startColumn+o.length)),this.research(!0)}else this._decorations.setStartPosition(this._editor.getPosition()),this._setCurrentFindMatch(i.range)}_findMatches(e,t,i){const o=(e||[null]).map((e=>FindModelBoundToEditorModel._getSearchRange(this._editor.getModel(),e)));return this._editor.getModel().findMatches(this._state.searchString,o,this._state.isRegex,this._state.matchCase,this._state.wholeWord?this._editor.getOption(117):null,t,i)}replaceAll(){if(!this._hasMatches())return;const e=this._decorations.getFindScopes();null===e&&this._state.matchesCount>=MATCHES_LIMIT?this._largeReplaceAll():this._regularReplaceAll(e),this.research(!1)}_largeReplaceAll(){const e=new SearchParams(this._state.searchString,this._state.isRegex,this._state.matchCase,this._state.wholeWord?this._editor.getOption(117):null),t=e.parseSearchRequest();if(!t)return;let i=t.regex;if(!i.multiline){let e="mu";i.ignoreCase&&(e+="i"),i.global&&(e+="g"),i=new RegExp(i.source,e)}const o=this._editor.getModel(),s=o.getValue(1),n=o.getFullModelRange(),r=this._getReplacePattern();let a;const c=this._state.preserveCase;a=r.hasReplacementPatterns||c?s.replace(i,(function(){return r.buildReplaceString(arguments,c)})):s.replace(i,r.buildReplaceString(null,c));let h=new ReplaceCommandThatPreservesSelection(n,a,this._editor.getSelection());this._executeEditorCommand("replaceAll",h)}_regularReplaceAll(e){const t=this._getReplacePattern();let i=this._findMatches(e,t.hasReplacementPatterns||this._state.preserveCase,1073741824),o=[];for(let n=0,r=i.length;n<r;n++)o[n]=t.buildReplaceString(i[n].matches,this._state.preserveCase);let s=new ReplaceAllCommand(this._editor.getSelection(),i.map((e=>e.range)),o);this._executeEditorCommand("replaceAll",s)}selectAllMatches(){if(!this._hasMatches())return;let e=this._decorations.getFindScopes(),t=this._findMatches(e,!1,1073741824),i=t.map((e=>new Selection(e.range.startLineNumber,e.range.startColumn,e.range.endLineNumber,e.range.endColumn))),o=this._editor.getSelection();for(let s=0,n=i.length;s<n;s++){let e=i[s];if(e.equalsRange(o)){i=[o].concat(i.slice(0,s)).concat(i.slice(s+1));break}}this._editor.setSelections(i)}_executeEditorCommand(e,t){try{this._ignoreModelContentChanged=!0,this._editor.pushUndoStop(),this._editor.executeCommand(e,t),this._editor.pushUndoStop()}finally{this._ignoreModelContentChanged=!1}}}