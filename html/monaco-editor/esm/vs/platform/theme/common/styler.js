import{activeContrastBorder,badgeBackground,badgeForeground,contrastBorder,listActiveSelectionBackground,listActiveSelectionForeground,listActiveSelectionIconForeground,listDropBackground,listFilterWidgetBackground,listFilterWidgetNoMatchesOutline,listFilterWidgetOutline,listFocusBackground,listFocusForeground,listFocusOutline,listHoverBackground,listHoverForeground,listInactiveFocusBackground,listInactiveFocusOutline,listInactiveSelectionBackground,listInactiveSelectionForeground,listInactiveSelectionIconForeground,menuBackground,menuBorder,menuForeground,menuSelectionBackground,menuSelectionBorder,menuSelectionForeground,menuSeparatorBackground,resolveColorValue,scrollbarShadow,scrollbarSliderActiveBackground,scrollbarSliderBackground,scrollbarSliderHoverBackground,tableColumnsBorder,tableOddRowsBackgroundColor,treeIndentGuidesStroke,widgetShadow}from"./colorRegistry.js";export function computeStyles(e,o){const t=Object.create(null);for(let r in o){const n=o[r];n&&(t[r]=resolveColorValue(n,e))}return t}export function attachStyler(e,o,t){function r(){const r=computeStyles(e.getColorTheme(),o);"function"===typeof t?t(r):t.style(r)}return r(),e.onDidColorThemeChange(r)}export function attachBadgeStyler(e,o,t){return attachStyler(o,{badgeBackground:(null===t||void 0===t?void 0:t.badgeBackground)||badgeBackground,badgeForeground:(null===t||void 0===t?void 0:t.badgeForeground)||badgeForeground,badgeBorder:contrastBorder},e)}export function attachListStyler(e,o,t){return attachStyler(o,Object.assign(Object.assign({},defaultListStyles),t||{}),e)}export const defaultListStyles={listFocusBackground:listFocusBackground,listFocusForeground:listFocusForeground,listFocusOutline:listFocusOutline,listActiveSelectionBackground:listActiveSelectionBackground,listActiveSelectionForeground:listActiveSelectionForeground,listActiveSelectionIconForeground:listActiveSelectionIconForeground,listFocusAndSelectionBackground:listActiveSelectionBackground,listFocusAndSelectionForeground:listActiveSelectionForeground,listInactiveSelectionBackground:listInactiveSelectionBackground,listInactiveSelectionIconForeground:listInactiveSelectionIconForeground,listInactiveSelectionForeground:listInactiveSelectionForeground,listInactiveFocusBackground:listInactiveFocusBackground,listInactiveFocusOutline:listInactiveFocusOutline,listHoverBackground:listHoverBackground,listHoverForeground:listHoverForeground,listDropBackground:listDropBackground,listSelectionOutline:activeContrastBorder,listHoverOutline:activeContrastBorder,listFilterWidgetBackground:listFilterWidgetBackground,listFilterWidgetOutline:listFilterWidgetOutline,listFilterWidgetNoMatchesOutline:listFilterWidgetNoMatchesOutline,listMatchesShadow:widgetShadow,treeIndentGuidesStroke:treeIndentGuidesStroke,tableColumnsBorder:tableColumnsBorder,tableOddRowsBackgroundColor:tableOddRowsBackgroundColor};export const defaultMenuStyles={shadowColor:widgetShadow,borderColor:menuBorder,foregroundColor:menuForeground,backgroundColor:menuBackground,selectionForegroundColor:menuSelectionForeground,selectionBackgroundColor:menuSelectionBackground,selectionBorderColor:menuSelectionBorder,separatorColor:menuSeparatorBackground,scrollbarShadow:scrollbarShadow,scrollbarSliderBackground:scrollbarSliderBackground,scrollbarSliderHoverBackground:scrollbarSliderHoverBackground,scrollbarSliderActiveBackground:scrollbarSliderActiveBackground};export function attachMenuStyler(e,o,t){return attachStyler(o,Object.assign(Object.assign({},defaultMenuStyles),t),e)}