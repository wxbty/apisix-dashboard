export class HoverRangeAnchor{constructor(e,r){this.priority=e,this.range=r,this.type=1}equals(e){return 1===e.type&&this.range.equalsRange(e.range)}canAdoptVisibleHover(e,r){return 1===e.type&&r.lineNumber===this.range.startLineNumber}}export class HoverForeignElementAnchor{constructor(e,r,t){this.priority=e,this.owner=r,this.range=t,this.type=2}equals(e){return 2===e.type&&this.owner===e.owner}canAdoptVisibleHover(e,r){return 2===e.type&&this.owner===e.owner}}