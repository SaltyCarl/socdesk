import { forwardRef, useRef, type ButtonHTMLAttributes } from 'react'
import { usePressScale } from '../lib/motion'
import {
  buttonClasses,
  type ButtonSize,
  type ButtonVariant,
} from './buttonClasses'

/**
 * Button — three restraint-first variants (see ./buttonClasses). Press
 * gives a spring scale-down (Motion.dev, WAAPI — no inline style).
 */
export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  function Button(
    { variant = 'primary', size = 'md', type = 'button', className, ...rest },
    forwardedRef,
  ) {
    const localRef = useRef<HTMLButtonElement>(null)
    usePressScale(localRef)

    const setRef = (node: HTMLButtonElement | null) => {
      localRef.current = node
      if (typeof forwardedRef === 'function') forwardedRef(node)
      else if (forwardedRef) forwardedRef.current = node
    }

    return (
      <button
        ref={setRef}
        type={type}
        className={buttonClasses(variant, size, className)}
        {...rest}
      />
    )
  },
)
