var __decorate=this&&this.__decorate||function(e,t,s,o){var r,n=arguments.length,i=n<3?t:null===o?o=Object.getOwnPropertyDescriptor(t,s):o;if("object"===typeof Reflect&&"function"===typeof Reflect.decorate)i=Reflect.decorate(e,t,s,o);else for(var a=e.length-1;a>=0;a--)(r=e[a])&&(i=(n<3?r(i):n>3?r(t,s,i):r(t,s))||i);return n>3&&i&&Object.defineProperty(t,s,i),i},__param=this&&this.__param||function(e,t){return function(s,o){t(s,o,e)}},__awaiter=this&&this.__awaiter||function(e,t,s,o){function r(e){return e instanceof s?e:new s((function(t){t(e)}))}return new(s||(s=Promise))((function(s,n){function i(e){try{c(o.next(e))}catch(t){n(t)}}function a(e){try{c(o["throw"](e))}catch(t){n(t)}}function c(e){e.done?s(e.value):r(e.value).then(i,a)}c((o=o.apply(e,t||[])).next())}))};import{onUnexpectedError}from"../../../base/common/errors.js";import{Disposable,isDisposable}from"../../../base/common/lifecycle.js";import{Schemas}from"../../../base/common/network.js";import Severity from"../../../base/common/severity.js";import*as nls from"../../../nls.js";import{IDialogService}from"../../dialogs/common/dialogs.js";import{registerSingleton}from"../../instantiation/common/extensions.js";import{INotificationService}from"../../notification/common/notification.js";import{IUndoRedoService,ResourceEditStackSnapshot,UndoRedoGroup,UndoRedoSource}from"./undoRedo.js";const DEBUG=!1;function getResourceLabel(e){return e.scheme===Schemas.file?e.fsPath:e.path}let stackElementCounter=0;class ResourceStackElement{constructor(e,t,s,o,r,n,i){this.id=++stackElementCounter,this.type=0,this.actual=e,this.label=e.label,this.confirmBeforeUndo=e.confirmBeforeUndo||!1,this.resourceLabel=t,this.strResource=s,this.resourceLabels=[this.resourceLabel],this.strResources=[this.strResource],this.groupId=o,this.groupOrder=r,this.sourceId=n,this.sourceOrder=i,this.isValid=!0}setValid(e){this.isValid=e}toString(){return`[id:${this.id}] [group:${this.groupId}] [${this.isValid?"  VALID":"INVALID"}] ${this.actual.constructor.name} - ${this.actual}`}}class ResourceReasonPair{constructor(e,t){this.resourceLabel=e,this.reason=t}}class RemovedResources{constructor(){this.elements=new Map}createMessage(){const e=[],t=[];for(const[,o]of this.elements){const s=0===o.reason?e:t;s.push(o.resourceLabel)}let s=[];return e.length>0&&s.push(nls.localize({key:"externalRemoval",comment:["{0} is a list of filenames"]},"The following files have been closed and modified on disk: {0}.",e.join(", "))),t.length>0&&s.push(nls.localize({key:"noParallelUniverses",comment:["{0} is a list of filenames"]},"The following files have been modified in an incompatible way: {0}.",t.join(", "))),s.join("\n")}get size(){return this.elements.size}has(e){return this.elements.has(e)}set(e,t){this.elements.set(e,t)}delete(e){return this.elements.delete(e)}}class WorkspaceStackElement{constructor(e,t,s,o,r,n,i){this.id=++stackElementCounter,this.type=1,this.actual=e,this.label=e.label,this.confirmBeforeUndo=e.confirmBeforeUndo||!1,this.resourceLabels=t,this.strResources=s,this.groupId=o,this.groupOrder=r,this.sourceId=n,this.sourceOrder=i,this.removedResources=null,this.invalidatedResources=null}canSplit(){return"function"===typeof this.actual.split}removeResource(e,t,s){this.removedResources||(this.removedResources=new RemovedResources),this.removedResources.has(t)||this.removedResources.set(t,new ResourceReasonPair(e,s))}setValid(e,t,s){s?this.invalidatedResources&&(this.invalidatedResources.delete(t),0===this.invalidatedResources.size&&(this.invalidatedResources=null)):(this.invalidatedResources||(this.invalidatedResources=new RemovedResources),this.invalidatedResources.has(t)||this.invalidatedResources.set(t,new ResourceReasonPair(e,0)))}toString(){return`[id:${this.id}] [group:${this.groupId}] [${this.invalidatedResources?"INVALID":"  VALID"}] ${this.actual.constructor.name} - ${this.actual}`}}class ResourceEditStack{constructor(e,t){this.resourceLabel=e,this.strResource=t,this._past=[],this._future=[],this.locked=!1,this.versionId=1}dispose(){for(const e of this._past)1===e.type&&e.removeResource(this.resourceLabel,this.strResource,0);for(const e of this._future)1===e.type&&e.removeResource(this.resourceLabel,this.strResource,0);this.versionId++}toString(){let e=[];e.push(`* ${this.strResource}:`);for(let t=0;t<this._past.length;t++)e.push(`   * [UNDO] ${this._past[t]}`);for(let t=this._future.length-1;t>=0;t--)e.push(`   * [REDO] ${this._future[t]}`);return e.join("\n")}flushAllElements(){this._past=[],this._future=[],this.versionId++}_setElementValidFlag(e,t){1===e.type?e.setValid(this.resourceLabel,this.strResource,t):e.setValid(t)}setElementsValidFlag(e,t){for(const s of this._past)t(s.actual)&&this._setElementValidFlag(s,e);for(const s of this._future)t(s.actual)&&this._setElementValidFlag(s,e)}pushElement(e){for(const t of this._future)1===t.type&&t.removeResource(this.resourceLabel,this.strResource,1);this._future=[],this._past.push(e),this.versionId++}createSnapshot(e){const t=[];for(let s=0,o=this._past.length;s<o;s++)t.push(this._past[s].id);for(let s=this._future.length-1;s>=0;s--)t.push(this._future[s].id);return new ResourceEditStackSnapshot(e,t)}restoreSnapshot(e){const t=e.elements.length;let s=!0,o=0,r=-1;for(let i=0,a=this._past.length;i<a;i++,o++){const n=this._past[i];s&&(o>=t||n.id!==e.elements[o])&&(s=!1,r=0),s||1!==n.type||n.removeResource(this.resourceLabel,this.strResource,0)}let n=-1;for(let i=this._future.length-1;i>=0;i--,o++){const r=this._future[i];s&&(o>=t||r.id!==e.elements[o])&&(s=!1,n=i),s||1!==r.type||r.removeResource(this.resourceLabel,this.strResource,0)}-1!==r&&(this._past=this._past.slice(0,r)),-1!==n&&(this._future=this._future.slice(n+1)),this.versionId++}getElements(){const e=[],t=[];for(const s of this._past)e.push(s.actual);for(const s of this._future)t.push(s.actual);return{past:e,future:t}}getClosestPastElement(){return 0===this._past.length?null:this._past[this._past.length-1]}getSecondClosestPastElement(){return this._past.length<2?null:this._past[this._past.length-2]}getClosestFutureElement(){return 0===this._future.length?null:this._future[this._future.length-1]}hasPastElements(){return this._past.length>0}hasFutureElements(){return this._future.length>0}splitPastWorkspaceElement(e,t){for(let s=this._past.length-1;s>=0;s--)if(this._past[s]===e){t.has(this.strResource)?this._past[s]=t.get(this.strResource):this._past.splice(s,1);break}this.versionId++}splitFutureWorkspaceElement(e,t){for(let s=this._future.length-1;s>=0;s--)if(this._future[s]===e){t.has(this.strResource)?this._future[s]=t.get(this.strResource):this._future.splice(s,1);break}this.versionId++}moveBackward(e){this._past.pop(),this._future.push(e),this.versionId++}moveForward(e){this._future.pop(),this._past.push(e),this.versionId++}}class EditStackSnapshot{constructor(e){this.editStacks=e,this._versionIds=[];for(let t=0,s=this.editStacks.length;t<s;t++)this._versionIds[t]=this.editStacks[t].versionId}isValid(){for(let e=0,t=this.editStacks.length;e<t;e++)if(this._versionIds[e]!==this.editStacks[e].versionId)return!1;return!0}}const missingEditStack=new ResourceEditStack("","");missingEditStack.locked=!0;let UndoRedoService=class{constructor(e,t){this._dialogService=e,this._notificationService=t,this._editStacks=new Map,this._uriComparisonKeyComputers=[]}getUriComparisonKey(e){for(const t of this._uriComparisonKeyComputers)if(t[0]===e.scheme)return t[1].getComparisonKey(e);return e.toString()}_print(e){console.log("------------------------------------"),console.log(`AFTER ${e}: `);let t=[];for(const s of this._editStacks)t.push(s[1].toString());console.log(t.join("\n"))}pushElement(e,t=UndoRedoGroup.None,s=UndoRedoSource.None){if(0===e.type){const o=getResourceLabel(e.resource),r=this.getUriComparisonKey(e.resource);this._pushElement(new ResourceStackElement(e,o,r,t.id,t.nextOrder(),s.id,s.nextOrder()))}else{const o=new Set,r=[],n=[];for(const t of e.resources){const e=getResourceLabel(t),s=this.getUriComparisonKey(t);o.has(s)||(o.add(s),r.push(e),n.push(s))}1===r.length?this._pushElement(new ResourceStackElement(e,r[0],n[0],t.id,t.nextOrder(),s.id,s.nextOrder())):this._pushElement(new WorkspaceStackElement(e,r,n,t.id,t.nextOrder(),s.id,s.nextOrder()))}DEBUG&&this._print("pushElement")}_pushElement(e){for(let t=0,s=e.strResources.length;t<s;t++){const s=e.resourceLabels[t],o=e.strResources[t];let r;this._editStacks.has(o)?r=this._editStacks.get(o):(r=new ResourceEditStack(s,o),this._editStacks.set(o,r)),r.pushElement(e)}}getLastElement(e){const t=this.getUriComparisonKey(e);if(this._editStacks.has(t)){const e=this._editStacks.get(t);if(e.hasFutureElements())return null;const s=e.getClosestPastElement();return s?s.actual:null}return null}_splitPastWorkspaceElement(e,t){const s=e.actual.split(),o=new Map;for(const r of s){const e=getResourceLabel(r.resource),t=this.getUriComparisonKey(r.resource),s=new ResourceStackElement(r,e,t,0,0,0,0);o.set(s.strResource,s)}for(const r of e.strResources){if(t&&t.has(r))continue;const s=this._editStacks.get(r);s.splitPastWorkspaceElement(e,o)}}_splitFutureWorkspaceElement(e,t){const s=e.actual.split(),o=new Map;for(const r of s){const e=getResourceLabel(r.resource),t=this.getUriComparisonKey(r.resource),s=new ResourceStackElement(r,e,t,0,0,0,0);o.set(s.strResource,s)}for(const r of e.strResources){if(t&&t.has(r))continue;const s=this._editStacks.get(r);s.splitFutureWorkspaceElement(e,o)}}removeElements(e){const t="string"===typeof e?e:this.getUriComparisonKey(e);if(this._editStacks.has(t)){const e=this._editStacks.get(t);e.dispose(),this._editStacks.delete(t)}DEBUG&&this._print("removeElements")}setElementsValidFlag(e,t,s){const o=this.getUriComparisonKey(e);if(this._editStacks.has(o)){const e=this._editStacks.get(o);e.setElementsValidFlag(t,s)}DEBUG&&this._print("setElementsValidFlag")}createSnapshot(e){const t=this.getUriComparisonKey(e);if(this._editStacks.has(t)){const s=this._editStacks.get(t);return s.createSnapshot(e)}return new ResourceEditStackSnapshot(e,[])}restoreSnapshot(e){const t=this.getUriComparisonKey(e.resource);if(this._editStacks.has(t)){const s=this._editStacks.get(t);s.restoreSnapshot(e),s.hasPastElements()||s.hasFutureElements()||(s.dispose(),this._editStacks.delete(t))}DEBUG&&this._print("restoreSnapshot")}getElements(e){const t=this.getUriComparisonKey(e);if(this._editStacks.has(t)){const e=this._editStacks.get(t);return e.getElements()}return{past:[],future:[]}}_findClosestUndoElementWithSource(e){if(!e)return[null,null];let t=null,s=null;for(const[o,r]of this._editStacks){const n=r.getClosestPastElement();n&&(n.sourceId===e&&(!t||n.sourceOrder>t.sourceOrder)&&(t=n,s=o))}return[t,s]}canUndo(e){if(e instanceof UndoRedoSource){const[,t]=this._findClosestUndoElementWithSource(e.id);return!!t}const t=this.getUriComparisonKey(e);if(this._editStacks.has(t)){const e=this._editStacks.get(t);return e.hasPastElements()}return!1}_onError(e,t){onUnexpectedError(e);for(const s of t.strResources)this.removeElements(s);this._notificationService.error(e)}_acquireLocks(e){for(const t of e.editStacks)if(t.locked)throw new Error("Cannot acquire edit stack lock");for(const t of e.editStacks)t.locked=!0;return()=>{for(const t of e.editStacks)t.locked=!1}}_safeInvokeWithLocks(e,t,s,o,r){const n=this._acquireLocks(s);let i;try{i=t()}catch(a){return n(),o.dispose(),this._onError(a,e)}return i?i.then((()=>(n(),o.dispose(),r())),(t=>(n(),o.dispose(),this._onError(t,e)))):(n(),o.dispose(),r())}_invokeWorkspacePrepare(e){return __awaiter(this,void 0,void 0,(function*(){if("undefined"===typeof e.actual.prepareUndoRedo)return Disposable.None;const t=e.actual.prepareUndoRedo();return"undefined"===typeof t?Disposable.None:t}))}_invokeResourcePrepare(e,t){if(1!==e.actual.type||"undefined"===typeof e.actual.prepareUndoRedo)return t(Disposable.None);const s=e.actual.prepareUndoRedo();return s?isDisposable(s)?t(s):s.then((e=>t(e))):t(Disposable.None)}_getAffectedEditStacks(e){const t=[];for(const s of e.strResources)t.push(this._editStacks.get(s)||missingEditStack);return new EditStackSnapshot(t)}_tryToSplitAndUndo(e,t,s,o){if(t.canSplit())return this._splitPastWorkspaceElement(t,s),this._notificationService.warn(o),new WorkspaceVerificationError(this._undo(e,0,!0));for(const r of t.strResources)this.removeElements(r);return this._notificationService.warn(o),new WorkspaceVerificationError}_checkWorkspaceUndo(e,t,s,o){if(t.removedResources)return this._tryToSplitAndUndo(e,t,t.removedResources,nls.localize({key:"cannotWorkspaceUndo",comment:["{0} is a label for an operation. {1} is another message."]},"Could not undo '{0}' across all files. {1}",t.label,t.removedResources.createMessage()));if(o&&t.invalidatedResources)return this._tryToSplitAndUndo(e,t,t.invalidatedResources,nls.localize({key:"cannotWorkspaceUndo",comment:["{0} is a label for an operation. {1} is another message."]},"Could not undo '{0}' across all files. {1}",t.label,t.invalidatedResources.createMessage()));const r=[];for(const i of s.editStacks)i.getClosestPastElement()!==t&&r.push(i.resourceLabel);if(r.length>0)return this._tryToSplitAndUndo(e,t,null,nls.localize({key:"cannotWorkspaceUndoDueToChanges",comment:["{0} is a label for an operation. {1} is a list of filenames."]},"Could not undo '{0}' across all files because changes were made to {1}",t.label,r.join(", ")));const n=[];for(const i of s.editStacks)i.locked&&n.push(i.resourceLabel);return n.length>0?this._tryToSplitAndUndo(e,t,null,nls.localize({key:"cannotWorkspaceUndoDueToInProgressUndoRedo",comment:["{0} is a label for an operation. {1} is a list of filenames."]},"Could not undo '{0}' across all files because there is already an undo or redo operation running on {1}",t.label,n.join(", "))):s.isValid()?null:this._tryToSplitAndUndo(e,t,null,nls.localize({key:"cannotWorkspaceUndoDueToInMeantimeUndoRedo",comment:["{0} is a label for an operation. {1} is a list of filenames."]},"Could not undo '{0}' across all files because an undo or redo operation occurred in the meantime",t.label))}_workspaceUndo(e,t,s){const o=this._getAffectedEditStacks(t),r=this._checkWorkspaceUndo(e,t,o,!1);return r?r.returnValue:this._confirmAndExecuteWorkspaceUndo(e,t,o,s)}_isPartOfUndoGroup(e){if(!e.groupId)return!1;for(const[,t]of this._editStacks){const s=t.getClosestPastElement();if(s){if(s===e){const s=t.getSecondClosestPastElement();if(s&&s.groupId===e.groupId)return!0}if(s.groupId===e.groupId)return!0}}return!1}_confirmAndExecuteWorkspaceUndo(e,t,s,o){return __awaiter(this,void 0,void 0,(function*(){if(t.canSplit()&&!this._isPartOfUndoGroup(t)){const r=yield this._dialogService.show(Severity.Info,nls.localize("confirmWorkspace","Would you like to undo '{0}' across all files?",t.label),[nls.localize({key:"ok",comment:["{0} denotes a number that is > 1"]},"Undo in {0} Files",s.editStacks.length),nls.localize("nok","Undo this File"),nls.localize("cancel","Cancel")],{cancelId:2});if(2===r.choice)return;if(1===r.choice)return this._splitPastWorkspaceElement(t,null),this._undo(e,0,!0);const n=this._checkWorkspaceUndo(e,t,s,!1);if(n)return n.returnValue;o=!0}let r;try{r=yield this._invokeWorkspacePrepare(t)}catch(i){return this._onError(i,t)}const n=this._checkWorkspaceUndo(e,t,s,!0);if(n)return r.dispose(),n.returnValue;for(const e of s.editStacks)e.moveBackward(t);return this._safeInvokeWithLocks(t,(()=>t.actual.undo()),s,r,(()=>this._continueUndoInGroup(t.groupId,o)))}))}_resourceUndo(e,t,s){if(t.isValid){if(!e.locked)return this._invokeResourcePrepare(t,(o=>(e.moveBackward(t),this._safeInvokeWithLocks(t,(()=>t.actual.undo()),new EditStackSnapshot([e]),o,(()=>this._continueUndoInGroup(t.groupId,s))))));{const e=nls.localize({key:"cannotResourceUndoDueToInProgressUndoRedo",comment:["{0} is a label for an operation."]},"Could not undo '{0}' because there is already an undo or redo operation running.",t.label);this._notificationService.warn(e)}}else e.flushAllElements()}_findClosestUndoElementInGroup(e){if(!e)return[null,null];let t=null,s=null;for(const[o,r]of this._editStacks){const n=r.getClosestPastElement();n&&(n.groupId===e&&(!t||n.groupOrder>t.groupOrder)&&(t=n,s=o))}return[t,s]}_continueUndoInGroup(e,t){if(!e)return;const[,s]=this._findClosestUndoElementInGroup(e);return s?this._undo(s,0,t):void 0}undo(e){if(e instanceof UndoRedoSource){const[,t]=this._findClosestUndoElementWithSource(e.id);return t?this._undo(t,e.id,!1):void 0}return"string"===typeof e?this._undo(e,0,!1):this._undo(this.getUriComparisonKey(e),0,!1)}_undo(e,t=0,s){if(!this._editStacks.has(e))return;const o=this._editStacks.get(e),r=o.getClosestPastElement();if(!r)return;if(r.groupId){const[e,o]=this._findClosestUndoElementInGroup(r.groupId);if(r!==e&&o)return this._undo(o,t,s)}const n=r.sourceId!==t||r.confirmBeforeUndo;if(n&&!s)return this._confirmAndContinueUndo(e,t,r);try{return 1===r.type?this._workspaceUndo(e,r,s):this._resourceUndo(o,r,s)}finally{DEBUG&&this._print("undo")}}_confirmAndContinueUndo(e,t,s){return __awaiter(this,void 0,void 0,(function*(){const o=yield this._dialogService.show(Severity.Info,nls.localize("confirmDifferentSource","Would you like to undo '{0}'?",s.label),[nls.localize("confirmDifferentSource.yes","Yes"),nls.localize("confirmDifferentSource.no","No")],{cancelId:1});if(1!==o.choice)return this._undo(e,t,!0)}))}_findClosestRedoElementWithSource(e){if(!e)return[null,null];let t=null,s=null;for(const[o,r]of this._editStacks){const n=r.getClosestFutureElement();n&&(n.sourceId===e&&(!t||n.sourceOrder<t.sourceOrder)&&(t=n,s=o))}return[t,s]}canRedo(e){if(e instanceof UndoRedoSource){const[,t]=this._findClosestRedoElementWithSource(e.id);return!!t}const t=this.getUriComparisonKey(e);if(this._editStacks.has(t)){const e=this._editStacks.get(t);return e.hasFutureElements()}return!1}_tryToSplitAndRedo(e,t,s,o){if(t.canSplit())return this._splitFutureWorkspaceElement(t,s),this._notificationService.warn(o),new WorkspaceVerificationError(this._redo(e));for(const r of t.strResources)this.removeElements(r);return this._notificationService.warn(o),new WorkspaceVerificationError}_checkWorkspaceRedo(e,t,s,o){if(t.removedResources)return this._tryToSplitAndRedo(e,t,t.removedResources,nls.localize({key:"cannotWorkspaceRedo",comment:["{0} is a label for an operation. {1} is another message."]},"Could not redo '{0}' across all files. {1}",t.label,t.removedResources.createMessage()));if(o&&t.invalidatedResources)return this._tryToSplitAndRedo(e,t,t.invalidatedResources,nls.localize({key:"cannotWorkspaceRedo",comment:["{0} is a label for an operation. {1} is another message."]},"Could not redo '{0}' across all files. {1}",t.label,t.invalidatedResources.createMessage()));const r=[];for(const i of s.editStacks)i.getClosestFutureElement()!==t&&r.push(i.resourceLabel);if(r.length>0)return this._tryToSplitAndRedo(e,t,null,nls.localize({key:"cannotWorkspaceRedoDueToChanges",comment:["{0} is a label for an operation. {1} is a list of filenames."]},"Could not redo '{0}' across all files because changes were made to {1}",t.label,r.join(", ")));const n=[];for(const i of s.editStacks)i.locked&&n.push(i.resourceLabel);return n.length>0?this._tryToSplitAndRedo(e,t,null,nls.localize({key:"cannotWorkspaceRedoDueToInProgressUndoRedo",comment:["{0} is a label for an operation. {1} is a list of filenames."]},"Could not redo '{0}' across all files because there is already an undo or redo operation running on {1}",t.label,n.join(", "))):s.isValid()?null:this._tryToSplitAndRedo(e,t,null,nls.localize({key:"cannotWorkspaceRedoDueToInMeantimeUndoRedo",comment:["{0} is a label for an operation. {1} is a list of filenames."]},"Could not redo '{0}' across all files because an undo or redo operation occurred in the meantime",t.label))}_workspaceRedo(e,t){const s=this._getAffectedEditStacks(t),o=this._checkWorkspaceRedo(e,t,s,!1);return o?o.returnValue:this._executeWorkspaceRedo(e,t,s)}_executeWorkspaceRedo(e,t,s){return __awaiter(this,void 0,void 0,(function*(){let o;try{o=yield this._invokeWorkspacePrepare(t)}catch(n){return this._onError(n,t)}const r=this._checkWorkspaceRedo(e,t,s,!0);if(r)return o.dispose(),r.returnValue;for(const e of s.editStacks)e.moveForward(t);return this._safeInvokeWithLocks(t,(()=>t.actual.redo()),s,o,(()=>this._continueRedoInGroup(t.groupId)))}))}_resourceRedo(e,t){if(t.isValid){if(!e.locked)return this._invokeResourcePrepare(t,(s=>(e.moveForward(t),this._safeInvokeWithLocks(t,(()=>t.actual.redo()),new EditStackSnapshot([e]),s,(()=>this._continueRedoInGroup(t.groupId))))));{const e=nls.localize({key:"cannotResourceRedoDueToInProgressUndoRedo",comment:["{0} is a label for an operation."]},"Could not redo '{0}' because there is already an undo or redo operation running.",t.label);this._notificationService.warn(e)}}else e.flushAllElements()}_findClosestRedoElementInGroup(e){if(!e)return[null,null];let t=null,s=null;for(const[o,r]of this._editStacks){const n=r.getClosestFutureElement();n&&(n.groupId===e&&(!t||n.groupOrder<t.groupOrder)&&(t=n,s=o))}return[t,s]}_continueRedoInGroup(e){if(!e)return;const[,t]=this._findClosestRedoElementInGroup(e);return t?this._redo(t):void 0}redo(e){if(e instanceof UndoRedoSource){const[,t]=this._findClosestRedoElementWithSource(e.id);return t?this._redo(t):void 0}return"string"===typeof e?this._redo(e):this._redo(this.getUriComparisonKey(e))}_redo(e){if(!this._editStacks.has(e))return;const t=this._editStacks.get(e),s=t.getClosestFutureElement();if(s){if(s.groupId){const[e,t]=this._findClosestRedoElementInGroup(s.groupId);if(s!==e&&t)return this._redo(t)}try{return 1===s.type?this._workspaceRedo(e,s):this._resourceRedo(t,s)}finally{DEBUG&&this._print("redo")}}}};UndoRedoService=__decorate([__param(0,IDialogService),__param(1,INotificationService)],UndoRedoService);export{UndoRedoService};class WorkspaceVerificationError{constructor(e){this.returnValue=e}}registerSingleton(IUndoRedoService,UndoRedoService);