export class TreeNode{constructor(t,e){this.piece=t,this.color=e,this.size_left=0,this.lf_left=0,this.parent=this,this.left=this,this.right=this}next(){if(this.right!==SENTINEL)return leftest(this.right);let t=this;while(t.parent!==SENTINEL){if(t.parent.left===t)break;t=t.parent}return t.parent===SENTINEL?SENTINEL:t.parent}prev(){if(this.left!==SENTINEL)return righttest(this.left);let t=this;while(t.parent!==SENTINEL){if(t.parent.right===t)break;t=t.parent}return t.parent===SENTINEL?SENTINEL:t.parent}detach(){this.parent=null,this.left=null,this.right=null}}export const SENTINEL=new TreeNode(null,0);SENTINEL.parent=SENTINEL,SENTINEL.left=SENTINEL,SENTINEL.right=SENTINEL,SENTINEL.color=0;export function leftest(t){while(t.left!==SENTINEL)t=t.left;return t}export function righttest(t){while(t.right!==SENTINEL)t=t.right;return t}export function calculateSize(t){return t===SENTINEL?0:t.size_left+t.piece.length+calculateSize(t.right)}export function calculateLF(t){return t===SENTINEL?0:t.lf_left+t.piece.lineFeedCnt+calculateLF(t.right)}export function resetSentinel(){SENTINEL.parent=SENTINEL}export function leftRotate(t,e){const r=e.right;r.size_left+=e.size_left+(e.piece?e.piece.length:0),r.lf_left+=e.lf_left+(e.piece?e.piece.lineFeedCnt:0),e.right=r.left,r.left!==SENTINEL&&(r.left.parent=e),r.parent=e.parent,e.parent===SENTINEL?t.root=r:e.parent.left===e?e.parent.left=r:e.parent.right=r,r.left=e,e.parent=r}export function rightRotate(t,e){const r=e.left;e.left=r.right,r.right!==SENTINEL&&(r.right.parent=e),r.parent=e.parent,e.size_left-=r.size_left+(r.piece?r.piece.length:0),e.lf_left-=r.lf_left+(r.piece?r.piece.lineFeedCnt:0),e.parent===SENTINEL?t.root=r:e===e.parent.right?e.parent.right=r:e.parent.left=r,r.right=e,e.parent=r}export function rbDelete(t,e){let r,l;if(e.left===SENTINEL?(l=e,r=l.right):e.right===SENTINEL?(l=e,r=l.left):(l=leftest(e.right),r=l.right),l===t.root)return t.root=r,r.color=0,e.detach(),resetSentinel(),void(t.root.parent=SENTINEL);const o=1===l.color;if(l===l.parent.left?l.parent.left=r:l.parent.right=r,l===e?(r.parent=l.parent,recomputeTreeMetadata(t,r)):(l.parent===e?r.parent=l:r.parent=l.parent,recomputeTreeMetadata(t,r),l.left=e.left,l.right=e.right,l.parent=e.parent,l.color=e.color,e===t.root?t.root=l:e===e.parent.left?e.parent.left=l:e.parent.right=l,l.left!==SENTINEL&&(l.left.parent=l),l.right!==SENTINEL&&(l.right.parent=l),l.size_left=e.size_left,l.lf_left=e.lf_left,recomputeTreeMetadata(t,l)),e.detach(),r.parent.left===r){const e=calculateSize(r),l=calculateLF(r);if(e!==r.parent.size_left||l!==r.parent.lf_left){const o=e-r.parent.size_left,n=l-r.parent.lf_left;r.parent.size_left=e,r.parent.lf_left=l,updateTreeMetadata(t,r.parent,o,n)}}if(recomputeTreeMetadata(t,r.parent),o)return void resetSentinel();let n;while(r!==t.root&&0===r.color)r===r.parent.left?(n=r.parent.right,1===n.color&&(n.color=0,r.parent.color=1,leftRotate(t,r.parent),n=r.parent.right),0===n.left.color&&0===n.right.color?(n.color=1,r=r.parent):(0===n.right.color&&(n.left.color=0,n.color=1,rightRotate(t,n),n=r.parent.right),n.color=r.parent.color,r.parent.color=0,n.right.color=0,leftRotate(t,r.parent),r=t.root)):(n=r.parent.left,1===n.color&&(n.color=0,r.parent.color=1,rightRotate(t,r.parent),n=r.parent.left),0===n.left.color&&0===n.right.color?(n.color=1,r=r.parent):(0===n.left.color&&(n.right.color=0,n.color=1,leftRotate(t,n),n=r.parent.left),n.color=r.parent.color,r.parent.color=0,n.left.color=0,rightRotate(t,r.parent),r=t.root));r.color=0,resetSentinel()}export function fixInsert(t,e){recomputeTreeMetadata(t,e);while(e!==t.root&&1===e.parent.color)if(e.parent===e.parent.parent.left){const r=e.parent.parent.right;1===r.color?(e.parent.color=0,r.color=0,e.parent.parent.color=1,e=e.parent.parent):(e===e.parent.right&&(e=e.parent,leftRotate(t,e)),e.parent.color=0,e.parent.parent.color=1,rightRotate(t,e.parent.parent))}else{const r=e.parent.parent.left;1===r.color?(e.parent.color=0,r.color=0,e.parent.parent.color=1,e=e.parent.parent):(e===e.parent.left&&(e=e.parent,rightRotate(t,e)),e.parent.color=0,e.parent.parent.color=1,leftRotate(t,e.parent.parent))}t.root.color=0}export function updateTreeMetadata(t,e,r,l){while(e!==t.root&&e!==SENTINEL)e.parent.left===e&&(e.parent.size_left+=r,e.parent.lf_left+=l),e=e.parent}export function recomputeTreeMetadata(t,e){let r=0,l=0;if(e!==t.root){while(e!==t.root&&e===e.parent.right)e=e.parent;if(e!==t.root){e=e.parent,r=calculateSize(e.left)-e.size_left,l=calculateLF(e.left)-e.lf_left,e.size_left+=r,e.lf_left+=l;while(e!==t.root&&(0!==r||0!==l))e.parent.left===e&&(e.parent.size_left+=r,e.parent.lf_left+=l),e=e.parent}}}