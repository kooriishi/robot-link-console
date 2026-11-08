declare module '@novnc/novnc/core/rfb.js' {
  export default class RFB extends EventTarget {
    constructor(target: HTMLElement, url: string, options?: { credentials?: { password?: string; username?: string }; wsProtocols?: string[]; shared?: boolean })
    viewOnly: boolean
    scaleViewport: boolean
    resizeSession: boolean
    clipViewport: boolean
    focusOnClick: boolean
    qualityLevel: number
    compressionLevel: number
    showDotCursor: boolean
    disconnect(): void
    sendCredentials(credentials: { password?: string }): void
    sendCtrlAltDel(): void
    clipboardPasteFrom(text: string): void
    focus(): void
  }
}
