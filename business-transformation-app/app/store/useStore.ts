import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

export interface TransformationData {
  knowledgeBaseScore: number
  businessSystemScore: number
  uniquenessScore: number
  efficiencyMultiplier: number
  year1RevenueMin: number
  year1RevenueMax: number
  year5RevenueMin: number
  year5RevenueMax: number
  exitPotentialMin: number
  exitPotentialMax: number
  revenueMultiplier: number
  marketPosition: string
}

export interface LearningEntry {
  id: string
  date: Date
  title: string
  description: string
  category: string
  impact: 'low' | 'medium' | 'high'
  compoundEffect: number
}

export interface DocumentTemplate {
  id: string
  title: string
  category: string
  content: string
  isExecutable: boolean
  lastUsed?: Date
  usageCount: number
}

export interface Milestone {
  id: string
  title: string
  description: string
  targetDate: Date
  completed: boolean
  completedDate?: Date
  category: string
}

interface Store {
  transformation: TransformationData
  learningEntries: LearningEntry[]
  documents: DocumentTemplate[]
  milestones: Milestone[]
  
  // Actions
  updateTransformation: (data: Partial<TransformationData>) => void
  addLearningEntry: (entry: Omit<LearningEntry, 'id'>) => void
  updateLearningEntry: (id: string, entry: Partial<LearningEntry>) => void
  deleteLearningEntry: (id: string) => void
  
  addDocument: (doc: Omit<DocumentTemplate, 'id' | 'usageCount'>) => void
  updateDocument: (id: string, doc: Partial<DocumentTemplate>) => void
  deleteDocument: (id: string) => void
  incrementDocumentUsage: (id: string) => void
  
  addMilestone: (milestone: Omit<Milestone, 'id'>) => void
  updateMilestone: (id: string, milestone: Partial<Milestone>) => void
  deleteMilestone: (id: string) => void
  toggleMilestone: (id: string) => void
  
  // Export/Import
  exportData: () => string
  importData: (data: string) => void
  resetData: () => void
}

const defaultTransformation: TransformationData = {
  knowledgeBaseScore: 6,
  businessSystemScore: 7,
  uniquenessScore: 10,
  efficiencyMultiplier: 3.5,
  year1RevenueMin: 60000,
  year1RevenueMax: 100000,
  year5RevenueMin: 400000,
  year5RevenueMax: 800000,
  exitPotentialMin: 600000,
  exitPotentialMax: 1200000,
  revenueMultiplier: 1.5,
  marketPosition: 'Top 10% through systematic organization',
}

export const useStore = create<Store>()(
  persist(
    (set, get) => ({
      transformation: defaultTransformation,
      learningEntries: [],
      documents: [],
      milestones: [],

      updateTransformation: (data) =>
        set((state) => ({
          transformation: { ...state.transformation, ...data },
        })),

      addLearningEntry: (entry) =>
        set((state) => ({
          learningEntries: [
            {
              ...entry,
              id: Date.now().toString(),
              date: new Date(entry.date),
            },
            ...state.learningEntries,
          ],
        })),

      updateLearningEntry: (id, entry) =>
        set((state) => ({
          learningEntries: state.learningEntries.map((e) =>
            e.id === id ? { ...e, ...entry } : e
          ),
        })),

      deleteLearningEntry: (id) =>
        set((state) => ({
          learningEntries: state.learningEntries.filter((e) => e.id !== id),
        })),

      addDocument: (doc) =>
        set((state) => ({
          documents: [
            {
              ...doc,
              id: Date.now().toString(),
              usageCount: 0,
            },
            ...state.documents,
          ],
        })),

      updateDocument: (id, doc) =>
        set((state) => ({
          documents: state.documents.map((d) =>
            d.id === id ? { ...d, ...doc } : d
          ),
        })),

      deleteDocument: (id) =>
        set((state) => ({
          documents: state.documents.filter((d) => d.id !== id),
        })),

      incrementDocumentUsage: (id) =>
        set((state) => ({
          documents: state.documents.map((d) =>
            d.id === id
              ? { ...d, usageCount: d.usageCount + 1, lastUsed: new Date() }
              : d
          ),
        })),

      addMilestone: (milestone) =>
        set((state) => ({
          milestones: [
            {
              ...milestone,
              id: Date.now().toString(),
              targetDate: new Date(milestone.targetDate),
            },
            ...state.milestones,
          ],
        })),

      updateMilestone: (id, milestone) =>
        set((state) => ({
          milestones: state.milestones.map((m) =>
            m.id === id ? { ...m, ...milestone } : m
          ),
        })),

      deleteMilestone: (id) =>
        set((state) => ({
          milestones: state.milestones.filter((m) => m.id !== id),
        })),

      toggleMilestone: (id) =>
        set((state) => ({
          milestones: state.milestones.map((m) =>
            m.id === id
              ? {
                  ...m,
                  completed: !m.completed,
                  completedDate: !m.completed ? new Date() : undefined,
                }
              : m
          ),
        })),

      exportData: () => {
        const state = get()
        return JSON.stringify({
          transformation: state.transformation,
          learningEntries: state.learningEntries,
          documents: state.documents,
          milestones: state.milestones,
          exportDate: new Date().toISOString(),
        })
      },

      importData: (data) => {
        try {
          const parsed = JSON.parse(data)
          set({
            transformation: parsed.transformation || defaultTransformation,
            learningEntries: parsed.learningEntries || [],
            documents: parsed.documents || [],
            milestones: parsed.milestones || [],
          })
        } catch (error) {
          console.error('Failed to import data:', error)
        }
      },

      resetData: () =>
        set({
          transformation: defaultTransformation,
          learningEntries: [],
          documents: [],
          milestones: [],
        }),
    }),
    {
      name: 'business-transformation-storage',
      storage: createJSONStorage(() => localStorage),
    }
  )
)

