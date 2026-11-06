import { isTauri } from '@tauri-apps/api/core'
import DemoApp from './DemoApp'
import RealApp from './RealApp'

export default function App() {
  return isTauri() ? <RealApp /> : <DemoApp />
}
