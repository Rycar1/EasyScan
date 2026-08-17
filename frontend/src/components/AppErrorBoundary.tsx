import {Component, type CSSProperties, type ErrorInfo, type ReactNode} from "react";

export interface AppErrorBoundaryProps {
  /** 主界面内容。 */
  children: ReactNode;
  /** 降级界面的主标题。 */
  title?: string;
  /** 降级界面的说明文字。 */
  description?: string;
  /** 是否展示错误名称、消息与堆栈。默认不展示。 */
  showErrorDetails?: boolean;
  /** 重新加载前执行，可用于记录错误或清理状态。 */
  onReload?: () => void;
  /** 重新加载按钮的文案。 */
  reloadLabel?: string;
}

interface AppErrorBoundaryState {
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

const pageStyle: CSSProperties = {
  display: "grid",
  minHeight: "100dvh",
  placeItems: "center",
  padding: "24px",
  background: "#0b121b",
  color: "#eff5fc",
  fontFamily: "Segoe UI Variable Text, Microsoft YaHei UI, Aptos, PingFang SC, ui-sans-serif, system-ui, sans-serif",
};

const cardStyle: CSSProperties = {
  width: "min(100%, 560px)",
  padding: "32px",
  border: "1px solid rgba(207, 225, 244, 0.16)",
  borderRadius: "16px",
  background: "linear-gradient(145deg, rgba(24, 37, 52, 0.98), rgba(16, 27, 40, 0.98))",
  boxShadow: "0 24px 56px rgba(2, 8, 15, 0.36)",
};

/**
 * 捕获其子树渲染阶段异常，并提供独立于页面样式的中文降级界面。
 */
export class AppErrorBoundary extends Component<AppErrorBoundaryProps, AppErrorBoundaryState> {
  public state: AppErrorBoundaryState = {
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): AppErrorBoundaryState {
    return {error, errorInfo: null};
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    this.setState({errorInfo});
    console.error("EasyScan 界面发生未处理错误：", error, errorInfo);
  }

  private handleReload = (): void => {
    this.props.onReload?.();

    if (typeof window !== "undefined") {
      window.location.reload();
    }
  };

  public render(): ReactNode {
    const {
      children,
      title = "界面暂时无法加载",
      description = "应用遇到了意外问题。重新加载后通常可以恢复正常。",
      showErrorDetails = false,
      reloadLabel = "重新加载",
    } = this.props;
    const {error, errorInfo} = this.state;

    if (!error) {
      return children;
    }

    const detail = [
      `${error.name || "Error"}: ${error.message || "未知错误"}`,
      error.stack,
      errorInfo?.componentStack?.trim(),
    ].filter(Boolean).join("\n\n");

    return (
      <main style={pageStyle} role="alert" aria-live="assertive">
        <section style={cardStyle} aria-labelledby="app-error-boundary-title">
          <div
            aria-hidden="true"
            style={{
              display: "grid",
              width: "44px",
              height: "44px",
              placeItems: "center",
              border: "1px solid rgba(255, 157, 148, 0.38)",
              borderRadius: "12px",
              background: "rgba(210, 79, 69, 0.18)",
              color: "#ffb5ae",
              fontSize: "24px",
              fontWeight: 700,
            }}
          >
            !
          </div>
          <h1 id="app-error-boundary-title" style={{margin: "20px 0 8px", fontSize: "22px", lineHeight: 1.35}}>
            {title}
          </h1>
          <p style={{margin: 0, color: "#a6b4c5", fontSize: "14px", lineHeight: 1.7}}>{description}</p>

          <button
            type="button"
            onClick={this.handleReload}
            style={{
              marginTop: "24px",
              minHeight: "38px",
              padding: "8px 16px",
              border: "1px solid rgba(192, 216, 255, 0.5)",
              borderRadius: "10px",
              background: "#356fc4",
              color: "#ffffff",
              cursor: "pointer",
              font: "inherit",
              fontWeight: 600,
            }}
          >
            {reloadLabel}
          </button>

          {showErrorDetails && detail && (
            <details style={{marginTop: "20px", color: "#a6b4c5"}}>
              <summary style={{cursor: "pointer", color: "#c0d8ff"}}>查看错误详情</summary>
              <pre
                style={{
                  maxHeight: "220px",
                  margin: "12px 0 0",
                  padding: "12px",
                  overflow: "auto",
                  border: "1px solid rgba(207, 225, 244, 0.12)",
                  borderRadius: "8px",
                  background: "rgba(7, 13, 20, 0.48)",
                  color: "#d5e0ec",
                  fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace",
                  fontSize: "12px",
                  lineHeight: 1.55,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {detail}
              </pre>
            </details>
          )}
        </section>
      </main>
    );
  }
}

export default AppErrorBoundary;
