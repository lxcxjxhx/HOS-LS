import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/layout/Sidebar'
import TopBar from './components/layout/TopBar'
import RightPanel from './components/layout/RightPanel'
import StarMapView from './pages/StarMapView'
import AuditView from './pages/AuditView'
import PentestView from './pages/PentestView'
import ChatView from './pages/ChatView'
import SettingsView from './pages/SettingsView'
import IDEView from './pages/IDEView'
import SessionsView from './pages/SessionsView'

export default function App() {
  return (
    <div className="flex h-screen w-screen bg-celestial-bg text-celestial-text overflow-hidden">
      <Sidebar />
      <div className="flex flex-1 flex-col min-w-0">
        <TopBar />
        <main className="flex-1 overflow-auto p-4">
          <Routes>
            <Route path="/" element={<StarMapView />} />
            <Route path="/audit" element={<AuditView />} />
            <Route path="/pentest" element={<PentestView />} />
            <Route path="/chat" element={<ChatView />} />
            <Route path="/sessions" element={<SessionsView />} />
            <Route path="/settings" element={<SettingsView />} />
            <Route path="/ide" element={<IDEView />} />
            <Route path="/ide/:fileId" element={<IDEView />} />
          </Routes>
        </main>
      </div>
      <RightPanel />
    </div>
  )
}
