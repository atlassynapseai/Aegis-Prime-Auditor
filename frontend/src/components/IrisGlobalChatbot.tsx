'use client';

import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { MessageCircle, X, Send, Sparkles } from 'lucide-react';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

// ⭐ CUSTOMIZED FOR AEGIS PRIME AUDITOR ⭐
const IRIS_KNOWLEDGE_BASE: { [key: string]: { response: string; keywords: string[] } } = {
  'auditor': {
    response: 'Aegis Prime Auditor scans your AI systems for governance risks, compliance gaps, and decision audit trails. Upload your model or application and get a comprehensive report in minutes.',
    keywords: ['auditor', 'scan', 'governance', 'risks', 'compliance', 'audit', 'what is'],
  },
  'how to scan': {
    response: 'Upload your AI model, dataset, or application details. Our auditor analyzes it and generates a detailed governance report.',
    keywords: ['scan', 'upload', 'how to', 'start', 'create', 'run', 'generate'],
  },
  'risks': {
    response: 'We identify AI governance risks like decision bias, compliance gaps, data privacy issues, model explainability, and audit trail gaps.',
    keywords: ['risks', 'identify', 'problems', 'issues', 'governance', 'what risks'],
  },
  'compliance': {
    response: 'Our auditor checks compliance with regulations like GDPR, HIPAA, SOX, and industry-specific AI governance standards.',
    keywords: ['compliance', 'regulation', 'gdpr', 'hipaa', 'sox', 'regulatory'],
  },
  'pricing': {
    response: 'Pricing varies by usage. Visit our pricing page for details. Free tier available for getting started.',
    keywords: ['pricing', 'price', 'cost', 'plan', 'tier'],
  },
  'support': {
    response: 'Our team is available 24/7 for support. Email, chat, or phone - we respond in under 1 hour.',
    keywords: ['support', 'help', 'contact', 'error', 'problem', 'issue'],
  },
};

const GREETINGS = ['hi', 'hello', 'hey', 'howdy', 'greetings', 'sup', 'yo', 'what\'s up', 'how are you', 'how\'s it going'];

function isGreeting(message: string): boolean {
  const lower = message.toLowerCase().trim();
  const words = lower.split(/\s+/).filter(w => w.length > 0);
  if (words.length <= 2) {
    return GREETINGS.some(greeting => lower.includes(greeting));
  }
  return false;
}

function findBestResponse(userMessage: string): string | null {
  const lowerMessage = userMessage.toLowerCase();

  if (isGreeting(userMessage)) {
    return 'greeting';
  }

  let bestScore = 0;
  let bestResponse = null;

  for (const [_, { response, keywords }] of Object.entries(IRIS_KNOWLEDGE_BASE)) {
    let score = 0;
    for (const keyword of keywords) {
      if (lowerMessage.includes(keyword)) {
        score += keyword.length;
      }
    }
    if (score > bestScore) {
      bestScore = score;
      bestResponse = response;
    }
  }

  return bestResponse;
}

function extractName(message: string): string | null {
  const patterns = [
    /(?:my name is|i'm|im|call me)\s+([a-zA-Z]+)/i,
    /(?:the name is|you can call me)\s+([a-zA-Z]+)/i,
  ];

  for (const pattern of patterns) {
    const match = message.match(pattern);
    if (match && match[1]) {
      return match[1].charAt(0).toUpperCase() + match[1].slice(1);
    }
  }
  return null;
}

export function IrisGlobalChatbot() {
  const [isOpen, setIsOpen] = useState(false);
  const [userName, setUserName] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      role: 'assistant',
      content: "Hello! I'm Iris, your AI guide. How can I help you today?",
      timestamp: new Date()
    }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [characterExpression, setCharacterExpression] = useState<'neutral' | 'happy' | 'thinking'>('neutral');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSendMessage = async (text?: string) => {
    const messageText = text || input.trim();
    if (!messageText) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: messageText,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');

    const extractedName = extractName(messageText);
    if (extractedName && !extractedName.toLowerCase().includes('iris')) {
      setUserName(extractedName);
      const welcomeMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: `Nice to meet you, ${extractedName}! 😊 Feel free to ask me anything about Aegis Prime Auditor.`,
        timestamp: new Date()
      };
      setCharacterExpression('happy');
      setMessages(prev => [...prev, welcomeMessage]);
      setTimeout(() => setCharacterExpression('neutral'), 2000);
      return;
    }

    setCharacterExpression('thinking');
    setIsLoading(true);

    setTimeout(() => {
      let response = findBestResponse(messageText);

      if (response) {
        let assistantContent = '';

        if (response === 'greeting') {
          if (userName) {
            assistantContent = `Hey ${userName}! How can I help you today?`;
          } else {
            assistantContent = "Hey there! How can I help you today?";
          }
        } else {
          if (userName) {
            assistantContent = `${userName}, ${response.charAt(0).toLowerCase()}${response.slice(1)}`;
          } else {
            assistantContent = response;
          }
        }

        const assistantMessage: Message = {
          id: (Date.now() + 1).toString(),
          role: 'assistant',
          content: assistantContent,
          timestamp: new Date()
        };
        setMessages(prev => [...prev, assistantMessage]);
        setCharacterExpression('happy');
      } else {
        setCharacterExpression('neutral');
      }
      setIsLoading(false);
      setTimeout(() => setCharacterExpression('neutral'), 2000);
    }, 300);
  };

  return (
    <>
      {/* Floating Caption - Attracts user attention */}
      <AnimatePresence>
        {!isOpen && (
          <motion.div
            initial={{ opacity: 0, x: 20, y: 10 }}
            animate={{ opacity: 1, x: 0, y: 0 }}
            exit={{ opacity: 0, x: 20, y: 10 }}
            transition={{ duration: 0.5 }}
            className="fixed bottom-40 right-6 z-30"
          >
            <motion.div
              animate={{ y: [0, -8, 0] }}
              transition={{ duration: 2, repeat: Infinity }}
              className="bg-gradient-to-r from-cyan-500 to-purple-500 text-white px-4 py-2 rounded-full text-xs font-semibold shadow-lg shadow-cyan-500/30 whitespace-nowrap flex items-center gap-2"
            >
              <span>✨ Need help?</span>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Cute Smiling Button */}
      <motion.button
        onClick={() => setIsOpen(!isOpen)}
        whileHover={{ scale: 1.15 }}
        whileTap={{ scale: 0.9 }}
        className="fixed bottom-24 right-6 z-40 flex items-center justify-center group"
      >
        <motion.div
          animate={{ scale: [1, 1.2, 1] }}
          transition={{ duration: 2, repeat: Infinity }}
          className="absolute inset-0 rounded-full bg-gradient-to-r from-cyan-500 to-purple-500 blur-xl opacity-60"
        />

        <div className="relative w-16 h-16 rounded-full bg-gradient-to-br from-cyan-400 via-cyan-500 to-cyan-600 shadow-lg shadow-cyan-500/50 flex items-center justify-center border-2 border-cyan-300/60 overflow-hidden">
          <div className="absolute top-2 left-3 w-4 h-4 rounded-full bg-white/40 blur-sm" />

          {!isOpen ? (
            <motion.div
              initial={{ scale: 0.8 }}
              animate={{ scale: 1 }}
              transition={{ type: 'spring', stiffness: 200 }}
              className="flex flex-col items-center justify-center"
            >
              <div className="flex gap-2 mb-1">
                <motion.div
                  animate={characterExpression === 'thinking' ? { scaleY: [1, 0.3, 1] } : {}}
                  transition={characterExpression === 'thinking' ? { duration: 0.6, repeat: Infinity } : {}}
                  className="w-2 h-2.5 rounded-full bg-slate-900"
                />
                <motion.div
                  animate={characterExpression === 'thinking' ? { scaleY: [1, 0.3, 1] } : {}}
                  transition={characterExpression === 'thinking' ? { duration: 0.6, repeat: Infinity, delay: 0.1 } : {}}
                  className="w-2 h-2.5 rounded-full bg-slate-900"
                />
              </div>
              {characterExpression === 'happy' ? (
                <motion.svg width="14" height="8" viewBox="0 0 14 8" className="text-slate-900" animate={{ scale: [1, 1.1, 1] }} transition={{ duration: 0.3 }}>
                  <path d="M 2 2 Q 7 6 12 2" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" />
                </motion.svg>
              ) : characterExpression === 'thinking' ? (
                <motion.svg width="12" height="8" viewBox="0 0 12 8" className="text-slate-900">
                  <circle cx="6" cy="4" r="1.5" fill="currentColor" />
                </motion.svg>
              ) : (
                <svg width="12" height="6" viewBox="0 0 12 6" className="text-slate-900">
                  <path d="M 2 2 Q 6 5 10 2" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" />
                </svg>
              )}
            </motion.div>
          ) : (
            <X className="w-6 h-6 text-white" />
          )}

          <motion.div
            animate={{ scale: [1, 1.2], opacity: [1, 0] }}
            transition={{ duration: 2, repeat: Infinity }}
            className="absolute inset-0 rounded-full border-2 border-cyan-300"
          />
        </div>
      </motion.button>

      {/* Chat Window */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            className="fixed bottom-40 right-6 z-40 w-full max-w-sm bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 border border-cyan-500/30 rounded-3xl shadow-2xl shadow-cyan-500/20 flex flex-col overflow-hidden backdrop-blur-xl"
          >
            <div className="px-6 py-5 bg-gradient-to-r from-cyan-500/20 via-purple-500/10 to-cyan-500/20 border-b border-cyan-500/20 flex items-center justify-between relative overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 to-transparent" />

              <div className="flex items-center gap-3 relative z-10">
                <motion.div
                  animate={{ y: [0, -3, 0] }}
                  transition={{ duration: 3, repeat: Infinity }}
                  className="w-10 h-10 rounded-full bg-gradient-to-br from-cyan-400 to-cyan-600 flex items-center justify-center border-2 border-cyan-300/60 flex-shrink-0"
                >
                  <Sparkles className="w-5 h-5 text-white" />
                </motion.div>
                <div>
                  <h2 className="text-sm font-bold text-transparent bg-gradient-to-r from-cyan-300 to-purple-300 bg-clip-text uppercase tracking-widest">
                    Iris
                  </h2>
                  <p className="text-[10px] text-cyan-300/70 font-medium">
                    {userName ? `Hi, ${userName}!` : 'Your AI Guide'}
                  </p>
                </div>
              </div>

              <motion.button
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => setIsOpen(false)}
                className="p-2 hover:bg-white/10 rounded-full transition-colors relative z-10"
              >
                <X className="w-5 h-5 text-cyan-300" />
              </motion.button>
            </div>

            <div className="flex-1 overflow-y-auto p-5 space-y-4 bg-slate-900/50 min-h-[280px]">
              {messages.map((msg, idx) => (
                <motion.div
                  key={msg.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.05 }}
                  className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                >
                  {msg.role === 'assistant' && (
                    <div className="w-6 h-6 rounded-full bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center mr-2 flex-shrink-0">
                      <Sparkles className="w-3 h-3 text-cyan-400" />
                    </div>
                  )}

                  <div
                    className={`max-w-xs px-4 py-3 rounded-2xl text-sm leading-relaxed transition-colors ${msg.role === 'user'
                        ? 'bg-gradient-to-r from-cyan-600 to-cyan-700 text-white rounded-br-none shadow-lg shadow-cyan-600/20'
                        : 'bg-white/10 hover:bg-white/15 text-slate-100 rounded-bl-none border border-white/10'
                      }`}
                  >
                    {msg.content}
                  </div>
                </motion.div>
              ))}

              {isLoading && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="flex justify-start"
                >
                  <div className="flex gap-2 px-4 py-3">
                    <motion.div
                      animate={{ y: [0, -8, 0] }}
                      transition={{ duration: 0.6, repeat: Infinity }}
                      className="w-2 h-2 rounded-full bg-cyan-400"
                    />
                    <motion.div
                      animate={{ y: [0, -8, 0] }}
                      transition={{ duration: 0.6, repeat: Infinity, delay: 0.1 }}
                      className="w-2 h-2 rounded-full bg-cyan-400"
                    />
                    <motion.div
                      animate={{ y: [0, -8, 0] }}
                      transition={{ duration: 0.6, repeat: Infinity, delay: 0.2 }}
                      className="w-2 h-2 rounded-full bg-cyan-400"
                    />
                  </div>
                </motion.div>
              )}

              <div ref={messagesEndRef} />
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSendMessage();
              }}
              className="px-5 py-4 bg-gradient-to-t from-slate-950 to-slate-900/80 border-t border-cyan-500/20"
            >
              <div className="flex gap-3">
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Ask me anything..."
                  className="flex-1 bg-white/5 border border-cyan-500/30 hover:border-cyan-500/50 focus:border-cyan-400 rounded-full px-4 py-3 text-sm text-white placeholder-slate-400 focus:outline-none transition-colors duration-300 backdrop-blur-sm"
                />
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  type="submit"
                  className="p-3 bg-gradient-to-r from-cyan-500 to-cyan-600 hover:from-cyan-400 hover:to-cyan-500 rounded-full text-white transition-all duration-300 shadow-lg shadow-cyan-500/40 flex-shrink-0"
                >
                  <Send className="w-4 h-4" />
                </motion.button>
              </div>
            </form>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
