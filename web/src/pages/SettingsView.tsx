import { AlertTriangle } from 'lucide-react'

export default function SettingsView() {
  return (
    <div className="h-full flex items-center justify-center">
      <div className="text-center max-w-md">
        <AlertTriangle size={48} className="mx-auto mb-4 text-celestial-accent" />
        <h1 className="text-xl font-bold text-celestial-text mb-2">设置功能尚未实现</h1>
        <p className="text-sm text-celestial-textDim mb-4">
          当前所有配置均通过环境变量或配置文件管理。
        </p>
        <div className="text-xs text-celestial-textDim/60 space-y-1">
          <p>环境变量配置参考：</p>
          <p className="font-mono">OPENAI_API_KEY=sk-xxx</p>
          <p className="font-mono">HOS_HOST=127.0.0.1</p>
          <p className="font-mono">HOS_PORT=8888</p>
        </div>
      </div>
    </div>
  )
}
