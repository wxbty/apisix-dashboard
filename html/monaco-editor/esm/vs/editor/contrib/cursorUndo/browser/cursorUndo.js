import{Disposable}from"../../../../base/common/lifecycle.js";import{EditorAction,registerEditorAction,registerEditorContribution}from"../../../browser/editorExtensions.js";import{EditorContextKeys}from"../../../common/editorContextKeys.js";import*as nls from"../../../../nls.js";class CursorState{constructor(o){this.selections=o}equals(o){const t=this.selections.length,r=o.selections.length;if(t!==r)return!1;for(let e=0;e<t;e++)if(!this.selections[e].equalsSelection(o.selections[e]))return!1;return!0}}class StackElement{constructor(o,t,r){this.cursorState=o,this.scrollTop=t,this.scrollLeft=r}}export class CursorUndoRedoController extends Disposable{constructor(o){super(),this._editor=o,this._isCursorUndoRedo=!1,this._undoStack=[],this._redoStack=[],this._register(o.onDidChangeModel((o=>{this._undoStack=[],this._redoStack=[]}))),this._register(o.onDidChangeModelContent((o=>{this._undoStack=[],this._redoStack=[]}))),this._register(o.onDidChangeCursorSelection((t=>{if(this._isCursorUndoRedo)return;if(!t.oldSelections)return;if(t.oldModelVersionId!==t.modelVersionId)return;const r=new CursorState(t.oldSelections),e=this._undoStack.length>0&&this._undoStack[this._undoStack.length-1].cursorState.equals(r);e||(this._undoStack.push(new StackElement(r,o.getScrollTop(),o.getScrollLeft())),this._redoStack=[],this._undoStack.length>50&&this._undoStack.shift())})))}static get(o){return o.getContribution(CursorUndoRedoController.ID)}cursorUndo(){this._editor.hasModel()&&0!==this._undoStack.length&&(this._redoStack.push(new StackElement(new CursorState(this._editor.getSelections()),this._editor.getScrollTop(),this._editor.getScrollLeft())),this._applyState(this._undoStack.pop()))}cursorRedo(){this._editor.hasModel()&&0!==this._redoStack.length&&(this._undoStack.push(new StackElement(new CursorState(this._editor.getSelections()),this._editor.getScrollTop(),this._editor.getScrollLeft())),this._applyState(this._redoStack.pop()))}_applyState(o){this._isCursorUndoRedo=!0,this._editor.setSelections(o.cursorState.selections),this._editor.setScrollPosition({scrollTop:o.scrollTop,scrollLeft:o.scrollLeft}),this._isCursorUndoRedo=!1}}CursorUndoRedoController.ID="editor.contrib.cursorUndoRedoController";export class CursorUndo extends EditorAction{constructor(){super({id:"cursorUndo",label:nls.localize("cursor.undo","Cursor Undo"),alias:"Cursor Undo",precondition:void 0,kbOpts:{kbExpr:EditorContextKeys.textInputFocus,primary:2099,weight:100}})}run(o,t,r){var e;null===(e=CursorUndoRedoController.get(t))||void 0===e||e.cursorUndo()}}export class CursorRedo extends EditorAction{constructor(){super({id:"cursorRedo",label:nls.localize("cursor.redo","Cursor Redo"),alias:"Cursor Redo",precondition:void 0})}run(o,t,r){var e;null===(e=CursorUndoRedoController.get(t))||void 0===e||e.cursorRedo()}}registerEditorContribution(CursorUndoRedoController.ID,CursorUndoRedoController),registerEditorAction(CursorUndo),registerEditorAction(CursorRedo);