import{onUnexpectedError}from"../../../base/common/errors.js";import*as strings from"../../../base/common/strings.js";import{CursorCollection}from"./cursorCollection.js";import{CursorContext,CursorState,EditOperationResult}from"./cursorCommon.js";import{DeleteOperations}from"./cursorDeleteOperations.js";import{TypeOperations,TypeWithAutoClosingCommand}from"./cursorTypeOperations.js";import{Range}from"../core/range.js";import{Selection}from"../core/selection.js";import{ModelInjectedTextChangedEvent}from"../textModelEvents.js";import{ViewCursorStateChangedEvent,ViewRevealRangeRequestEvent}from"../viewModel/viewEvents.js";import{dispose,Disposable}from"../../../base/common/lifecycle.js";import{CursorStateChangedEvent}from"../viewModel/viewModelEventDispatcher.js";export class CursorsController extends Disposable{constructor(t,e,s,o){super(),this._model=t,this._knownModelVersionId=this._model.getVersionId(),this._viewModel=e,this._coordinatesConverter=s,this.context=new CursorContext(this._model,this._viewModel,this._coordinatesConverter,o),this._cursors=new CursorCollection(this.context),this._hasFocus=!1,this._isHandling=!1,this._isDoingComposition=!1,this._selectionsWhenCompositionStarted=null,this._columnSelectData=null,this._autoClosedActions=[],this._prevEditOperationType=0}dispose(){this._cursors.dispose(),this._autoClosedActions=dispose(this._autoClosedActions),super.dispose()}updateConfiguration(t){this.context=new CursorContext(this._model,this._viewModel,this._coordinatesConverter,t),this._cursors.updateContext(this.context)}onLineMappingChanged(t){this._knownModelVersionId===this._model.getVersionId()&&this.setStates(t,"viewModel",0,this.getCursorStates())}setHasFocus(t){this._hasFocus=t}_validateAutoClosedActions(){if(this._autoClosedActions.length>0){const t=this._cursors.getSelections();for(let e=0;e<this._autoClosedActions.length;e++){const s=this._autoClosedActions[e];s.isValid(t)||(s.dispose(),this._autoClosedActions.splice(e,1),e--)}}}getPrimaryCursorState(){return this._cursors.getPrimaryCursor()}getLastAddedCursorIndex(){return this._cursors.getLastAddedCursorIndex()}getCursorStates(){return this._cursors.getAll()}setStates(t,e,s,o){let i=!1;null!==o&&o.length>CursorsController.MAX_CURSOR_COUNT&&(o=o.slice(0,CursorsController.MAX_CURSOR_COUNT),i=!0);const n=CursorModelState.from(this._model,this);return this._cursors.setStates(o),this._cursors.normalize(),this._columnSelectData=null,this._validateAutoClosedActions(),this._emitStateChangedIfNecessary(t,e,s,n,i)}setCursorColumnSelectData(t){this._columnSelectData=t}revealPrimary(t,e,s,o,i,n){const r=this._cursors.getViewPositions();let a=null,l=null;r.length>1?l=this._cursors.getViewSelections():a=Range.fromPositions(r[0],r[0]),t.emitViewEvent(new ViewRevealRangeRequestEvent(e,s,a,l,o,i,n))}saveState(){const t=[],e=this._cursors.getSelections();for(let s=0,o=e.length;s<o;s++){const o=e[s];t.push({inSelectionMode:!o.isEmpty(),selectionStart:{lineNumber:o.selectionStartLineNumber,column:o.selectionStartColumn},position:{lineNumber:o.positionLineNumber,column:o.positionColumn}})}return t}restoreState(t,e){const s=[];for(let o=0,i=e.length;o<i;o++){const t=e[o];let i=1,n=1;t.position&&t.position.lineNumber&&(i=t.position.lineNumber),t.position&&t.position.column&&(n=t.position.column);let r=i,a=n;t.selectionStart&&t.selectionStart.lineNumber&&(r=t.selectionStart.lineNumber),t.selectionStart&&t.selectionStart.column&&(a=t.selectionStart.column),s.push({selectionStartLineNumber:r,selectionStartColumn:a,positionLineNumber:i,positionColumn:n})}this.setStates(t,"restoreState",0,CursorState.fromModelSelections(s)),this.revealPrimary(t,"restoreState",!1,0,!0,1)}onModelContentChanged(t,e){if(e instanceof ModelInjectedTextChangedEvent){if(this._isHandling)return;this._isHandling=!0;try{this.setStates(t,"modelChange",0,this.getCursorStates())}finally{this._isHandling=!1}}else{if(this._knownModelVersionId=e.versionId,this._isHandling)return;const s=e.containsEvent(1);if(this._prevEditOperationType=0,s)this._cursors.dispose(),this._cursors=new CursorCollection(this.context),this._validateAutoClosedActions(),this._emitStateChangedIfNecessary(t,"model",1,null,!1);else if(this._hasFocus&&e.resultingSelection&&e.resultingSelection.length>0){const s=CursorState.fromModelSelections(e.resultingSelection);this.setStates(t,"modelChange",e.isUndoing?5:e.isRedoing?6:2,s)&&this.revealPrimary(t,"modelChange",!1,0,!0,0)}else{const e=this._cursors.readSelectionFromMarkers();this.setStates(t,"modelChange",2,CursorState.fromModelSelections(e))}}}getSelection(){return this._cursors.getPrimaryCursor().modelState.selection}getTopMostViewPosition(){return this._cursors.getTopMostViewPosition()}getBottomMostViewPosition(){return this._cursors.getBottomMostViewPosition()}getCursorColumnSelectData(){if(this._columnSelectData)return this._columnSelectData;const t=this._cursors.getPrimaryCursor(),e=t.viewState.selectionStart.getStartPosition(),s=t.viewState.position;return{isReal:!1,fromViewLineNumber:e.lineNumber,fromViewVisualColumn:this.context.cursorConfig.visibleColumnFromColumn(this._viewModel,e),toViewLineNumber:s.lineNumber,toViewVisualColumn:this.context.cursorConfig.visibleColumnFromColumn(this._viewModel,s)}}getSelections(){return this._cursors.getSelections()}setSelections(t,e,s,o){this.setStates(t,e,o,CursorState.fromModelSelections(s))}getPrevEditOperationType(){return this._prevEditOperationType}setPrevEditOperationType(t){this._prevEditOperationType=t}_pushAutoClosedAction(t,e){const s=[],o=[];for(let r=0,a=t.length;r<a;r++)s.push({range:t[r],options:{description:"auto-closed-character",inlineClassName:"auto-closed-character",stickiness:1}}),o.push({range:e[r],options:{description:"auto-closed-enclosing",stickiness:1}});const i=this._model.deltaDecorations([],s),n=this._model.deltaDecorations([],o);this._autoClosedActions.push(new AutoClosedAction(this._model,i,n))}_executeEditOperation(t){if(!t)return;t.shouldPushStackElementBefore&&this._model.pushStackElement();const e=CommandExecutor.executeCommands(this._model,this._cursors.getSelections(),t.commands);if(e){this._interpretCommandResult(e);const s=[],o=[];for(let e=0;e<t.commands.length;e++){const i=t.commands[e];i instanceof TypeWithAutoClosingCommand&&i.enclosingRange&&i.closeCharacterRange&&(s.push(i.closeCharacterRange),o.push(i.enclosingRange))}s.length>0&&this._pushAutoClosedAction(s,o),this._prevEditOperationType=t.type}t.shouldPushStackElementAfter&&this._model.pushStackElement()}_interpretCommandResult(t){t&&0!==t.length||(t=this._cursors.readSelectionFromMarkers()),this._columnSelectData=null,this._cursors.setSelections(t),this._cursors.normalize()}_emitStateChangedIfNecessary(t,e,s,o,i){const n=CursorModelState.from(this._model,this);if(n.equals(o))return!1;const r=this._cursors.getSelections(),a=this._cursors.getViewSelections();if(t.emitViewEvent(new ViewCursorStateChangedEvent(a,r)),!o||o.cursorState.length!==n.cursorState.length||n.cursorState.some(((t,e)=>!t.modelState.equals(o.cursorState[e].modelState)))){const a=o?o.cursorState.map((t=>t.modelState.selection)):null,l=o?o.modelVersionId:0;t.emitOutgoingEvent(new CursorStateChangedEvent(a,r,l,n.modelVersionId,e||"keyboard",s,i))}return!0}_findAutoClosingPairs(t){if(!t.length)return null;const e=[];for(let s=0,o=t.length;s<o;s++){const o=t[s];if(!o.text||o.text.indexOf("\n")>=0)return null;const i=o.text.match(/([)\]}>'"`])([^)\]}>'"`]*)$/);if(!i)return null;const n=i[1],r=this.context.cursorConfig.autoClosingPairs.autoClosingPairsCloseSingleChar.get(n);if(!r||1!==r.length)return null;const a=r[0].open,l=o.text.length-i[2].length-1,c=o.text.lastIndexOf(a,l-1);if(-1===c)return null;e.push([c,l])}return e}executeEdits(t,e,s,o){let i=null;"snippet"===e&&(i=this._findAutoClosingPairs(s)),i&&(s[0]._isTracked=!0);const n=[],r=[],a=this._model.pushEditOperations(this.getSelections(),s,(t=>{if(i)for(let s=0,o=i.length;s<o;s++){const[e,o]=i[s],a=t[s],l=a.range.startLineNumber,c=a.range.startColumn-1+e,u=a.range.startColumn-1+o;n.push(new Range(l,u+1,l,u+2)),r.push(new Range(l,c+1,l,u+2))}const e=o(t);return e&&(this._isHandling=!0),e}));a&&(this._isHandling=!1,this.setSelections(t,e,a,0)),n.length>0&&this._pushAutoClosedAction(n,r)}_executeEdit(t,e,s,o=0){if(this.context.cursorConfig.readOnly)return;const i=CursorModelState.from(this._model,this);this._cursors.stopTrackingSelections(),this._isHandling=!0;try{this._cursors.ensureValidState(),t()}catch(n){onUnexpectedError(n)}this._isHandling=!1,this._cursors.startTrackingSelections(),this._validateAutoClosedActions(),this._emitStateChangedIfNecessary(e,s,o,i,!1)&&this.revealPrimary(e,s,!1,0,!0,0)}setIsDoingComposition(t){this._isDoingComposition=t}getAutoClosedCharacters(){return AutoClosedAction.getAllAutoClosedCharacters(this._autoClosedActions)}startComposition(t){this._selectionsWhenCompositionStarted=this.getSelections().slice(0)}endComposition(t,e){this._executeEdit((()=>{"keyboard"===e&&(this._executeEditOperation(TypeOperations.compositionEndWithInterceptors(this._prevEditOperationType,this.context.cursorConfig,this._model,this._selectionsWhenCompositionStarted,this.getSelections(),this.getAutoClosedCharacters())),this._selectionsWhenCompositionStarted=null)}),t,e)}type(t,e,s){this._executeEdit((()=>{if("keyboard"===s){const t=e.length;let s=0;while(s<t){const t=strings.nextCharLength(e,s),o=e.substr(s,t);this._executeEditOperation(TypeOperations.typeWithInterceptors(this._isDoingComposition,this._prevEditOperationType,this.context.cursorConfig,this._model,this.getSelections(),this.getAutoClosedCharacters(),o)),s+=t}}else this._executeEditOperation(TypeOperations.typeWithoutInterceptors(this._prevEditOperationType,this.context.cursorConfig,this._model,this.getSelections(),e))}),t,s)}compositionType(t,e,s,o,i,n){if(0!==e.length||0!==s||0!==o)this._executeEdit((()=>{this._executeEditOperation(TypeOperations.compositionType(this._prevEditOperationType,this.context.cursorConfig,this._model,this.getSelections(),e,s,o,i))}),t,n);else if(0!==i){const e=this.getSelections().map((t=>{const e=t.getPosition();return new Selection(e.lineNumber,e.column+i,e.lineNumber,e.column+i)}));this.setSelections(t,n,e,0)}}paste(t,e,s,o,i){this._executeEdit((()=>{this._executeEditOperation(TypeOperations.paste(this.context.cursorConfig,this._model,this.getSelections(),e,s,o||[]))}),t,i,4)}cut(t,e){this._executeEdit((()=>{this._executeEditOperation(DeleteOperations.cut(this.context.cursorConfig,this._model,this.getSelections()))}),t,e)}executeCommand(t,e,s){this._executeEdit((()=>{this._cursors.killSecondaryCursors(),this._executeEditOperation(new EditOperationResult(0,[e],{shouldPushStackElementBefore:!1,shouldPushStackElementAfter:!1}))}),t,s)}executeCommands(t,e,s){this._executeEdit((()=>{this._executeEditOperation(new EditOperationResult(0,e,{shouldPushStackElementBefore:!1,shouldPushStackElementAfter:!1}))}),t,s)}}CursorsController.MAX_CURSOR_COUNT=1e4;class CursorModelState{constructor(t,e){this.modelVersionId=t,this.cursorState=e}static from(t,e){return new CursorModelState(t.getVersionId(),e.getCursorStates())}equals(t){if(!t)return!1;if(this.modelVersionId!==t.modelVersionId)return!1;if(this.cursorState.length!==t.cursorState.length)return!1;for(let e=0,s=this.cursorState.length;e<s;e++)if(!this.cursorState[e].equals(t.cursorState[e]))return!1;return!0}}class AutoClosedAction{constructor(t,e,s){this._model=t,this._autoClosedCharactersDecorations=e,this._autoClosedEnclosingDecorations=s}static getAllAutoClosedCharacters(t){let e=[];for(const s of t)e=e.concat(s.getAutoClosedCharactersRanges());return e}dispose(){this._autoClosedCharactersDecorations=this._model.deltaDecorations(this._autoClosedCharactersDecorations,[]),this._autoClosedEnclosingDecorations=this._model.deltaDecorations(this._autoClosedEnclosingDecorations,[])}getAutoClosedCharactersRanges(){const t=[];for(let e=0;e<this._autoClosedCharactersDecorations.length;e++){const s=this._model.getDecorationRange(this._autoClosedCharactersDecorations[e]);s&&t.push(s)}return t}isValid(t){const e=[];for(let s=0;s<this._autoClosedEnclosingDecorations.length;s++){const t=this._model.getDecorationRange(this._autoClosedEnclosingDecorations[s]);if(t&&(e.push(t),t.startLineNumber!==t.endLineNumber))return!1}e.sort(Range.compareRangesUsingStarts),t.sort(Range.compareRangesUsingStarts);for(let s=0;s<t.length;s++){if(s>=e.length)return!1;if(!e[s].strictContainsRange(t[s]))return!1}return!0}}class CommandExecutor{static executeCommands(t,e,s){const o={model:t,selectionsBefore:e,trackedRanges:[],trackedRangesDirection:[]},i=this._innerExecuteCommands(o,s);for(let n=0,r=o.trackedRanges.length;n<r;n++)o.model._setTrackedRange(o.trackedRanges[n],null,0);return i}static _innerExecuteCommands(t,e){if(this._arrayIsEmpty(e))return null;const s=this._getEditOperations(t,e);if(0===s.operations.length)return null;const o=s.operations,i=this._getLoserCursorMap(o);if(i.hasOwnProperty("0"))return console.warn("Ignoring commands"),null;const n=[];for(let l=0,c=o.length;l<c;l++)i.hasOwnProperty(o[l].identifier.major.toString())||n.push(o[l]);s.hadTrackedEditOperation&&n.length>0&&(n[0]._isTracked=!0);let r=t.model.pushEditOperations(t.selectionsBefore,n,(s=>{const o=[];for(let e=0;e<t.selectionsBefore.length;e++)o[e]=[];for(const t of s)t.identifier&&o[t.identifier.major].push(t);const i=(t,e)=>t.identifier.minor-e.identifier.minor,n=[];for(let r=0;r<t.selectionsBefore.length;r++)o[r].length>0?(o[r].sort(i),n[r]=e[r].computeCursorState(t.model,{getInverseEditOperations:()=>o[r],getTrackedSelection:e=>{const s=parseInt(e,10),o=t.model._getTrackedRange(t.trackedRanges[s]);return 0===t.trackedRangesDirection[s]?new Selection(o.startLineNumber,o.startColumn,o.endLineNumber,o.endColumn):new Selection(o.endLineNumber,o.endColumn,o.startLineNumber,o.startColumn)}})):n[r]=t.selectionsBefore[r];return n}));r||(r=t.selectionsBefore);const a=[];for(let l in i)i.hasOwnProperty(l)&&a.push(parseInt(l,10));a.sort(((t,e)=>e-t));for(const l of a)r.splice(l,1);return r}static _arrayIsEmpty(t){for(let e=0,s=t.length;e<s;e++)if(t[e])return!1;return!0}static _getEditOperations(t,e){let s=[],o=!1;for(let i=0,n=e.length;i<n;i++){const n=e[i];if(n){const e=this._getEditOperationsFromCommand(t,i,n);s=s.concat(e.operations),o=o||e.hadTrackedEditOperation}}return{operations:s,hadTrackedEditOperation:o}}static _getEditOperationsFromCommand(t,e,s){const o=[];let i=0;const n=(t,n,r=!1)=>{Range.isEmpty(t)&&""===n||o.push({identifier:{major:e,minor:i++},range:t,text:n,forceMoveMarkers:r,isAutoWhitespaceEdit:s.insertsAutoWhitespace})};let r=!1;const a=(t,e,s)=>{r=!0,n(t,e,s)},l=(e,s)=>{const o=Selection.liftSelection(e);let i;if(o.isEmpty())if("boolean"===typeof s)i=s?2:3;else{const e=t.model.getLineMaxColumn(o.startLineNumber);i=o.startColumn===e?2:3}else i=1;const n=t.trackedRanges.length,r=t.model._setTrackedRange(null,o,i);return t.trackedRanges[n]=r,t.trackedRangesDirection[n]=o.getDirection(),n.toString()},c={addEditOperation:n,addTrackedEditOperation:a,trackSelection:l};try{s.getEditOperations(t.model,c)}catch(u){return onUnexpectedError(u),{operations:[],hadTrackedEditOperation:!1}}return{operations:o,hadTrackedEditOperation:r}}static _getLoserCursorMap(t){t=t.slice(0),t.sort(((t,e)=>-Range.compareRangesUsingEnds(t.range,e.range)));const e={};for(let s=1;s<t.length;s++){const o=t[s-1],i=t[s];if(Range.getStartPosition(o.range).isBefore(Range.getEndPosition(i.range))){let n;n=o.identifier.major>i.identifier.major?o.identifier.major:i.identifier.major,e[n.toString()]=!0;for(let e=0;e<t.length;e++)t[e].identifier.major===n&&(t.splice(e,1),e<s&&s--,e--);s>0&&s--}}return e}}