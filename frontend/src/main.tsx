import React from 'react'
import {createRoot} from 'react-dom/client'
import './style.css'
import App from './App'
import AppErrorBoundary from './components/AppErrorBoundary'

// 在开发和生产环境都保留全局诊断，便于定位边界外的运行时异常。
if (typeof window !== 'undefined') {
    const environment = import.meta.env.DEV ? '开发环境' : '生产环境'

    window.addEventListener('error', (event: ErrorEvent) => {
        console.error(`[EasyScan][${environment}] 捕获到全局错误：`, {
            message: event.message,
            filename: event.filename,
            lineno: event.lineno,
            colno: event.colno,
            error: event.error,
        })
    })

    window.addEventListener('unhandledrejection', (event: PromiseRejectionEvent) => {
        console.error(`[EasyScan][${environment}] 捕获到未处理的 Promise 拒绝：`, event.reason)
    })
}

const container = document.getElementById('root')

const root = createRoot(container!)

root.render(
    <React.StrictMode>
        <AppErrorBoundary showErrorDetails>
            <App/>
        </AppErrorBoundary>
    </React.StrictMode>
)
