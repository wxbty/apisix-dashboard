export class InternalEditorAction{constructor(t,i,e,r,s,o){this.id=t,this.label=i,this.alias=e,this._precondition=r,this._run=s,this._contextKeyService=o}isSupported(){return this._contextKeyService.contextMatchesRules(this._precondition)}run(){return this.isSupported()?this._run():Promise.resolve(void 0)}}